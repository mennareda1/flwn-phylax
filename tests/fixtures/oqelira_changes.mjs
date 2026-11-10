import fs from 'node:fs/promises'
import path from 'node:path'
import { createHash, randomUUID } from 'node:crypto'

/** @typedef {{path:string,exists:boolean,content:string|null,sha256:string|null}} Snapshot */
/** @typedef {{id:string,path:string,before:Snapshot,after:{sha256:string|null},state:'prepared'|'applied'}} Change */
/** @typedef {{path:string,expected_sha256:string|null,content:string|null,change_id?:string}} FileChangeInput */

/** @param {string} value */
const digest=value=>createHash('sha256').update(value).digest('hex')
const blocked=/(^|\/)(\.git|\.oqelira|\.ssh|\.azure|\.aws|\.env(?!\.example(?:\/|$))(?:\.[^\/]*)?)(\/|$)|\.(pem|key|pfx|p12)$/i

/** @param {string} cwd @param {string} name */
async function target(cwd,name){
  if(typeof name!=='string'||!name||name.length>1000||name.includes('\0'))throw new Error('Invalid project path')
  const root=await fs.realpath(cwd),file=path.resolve(root,name),relative=path.relative(root,file)
  if(!relative||relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative)||blocked.test(relative.replaceAll('\\','/')))throw new Error('Credential, internal and outside paths are excluded')
  let current=root
  for(const part of relative.split(path.sep)){
    current=path.join(current,part)
    try{if((await fs.lstat(current)).isSymbolicLink())throw new Error('Symlink changes are excluded')}
    catch(error){if(/** @type {NodeJS.ErrnoException} */(error).code==='ENOENT')break;throw error}
  }
  return {root,file,relative:relative.replaceAll('\\','/')}
}

/** @param {string} cwd @param {string} name @returns {Promise<Snapshot>} */
export async function snapshotFile(cwd,name){
  const resolved=await target(cwd,name)
  try{
    const stat=await fs.lstat(resolved.file)
    if(!stat.isFile()||stat.nlink!==1||stat.size>40000)throw new Error('Changes support unlinked UTF-8 text files of at most 10000 characters')
    const handle=await fs.open(resolved.file,'r');let bytes
    try{const buffer=Buffer.alloc(40001);const read=await handle.read(buffer,0,buffer.length,0);bytes=buffer.subarray(0,read.bytesRead)}finally{await handle.close()}
    const content=bytes.toString('utf8')
    if(bytes.length>40000||content.length>10000||content.includes('\0')||!Buffer.from(content).equals(bytes))throw new Error('Changes support UTF-8 text files of at most 10000 characters')
    return {path:resolved.relative,exists:true,content,sha256:digest(content)}
  }catch(error){if(/** @type {NodeJS.ErrnoException} */(error).code!=='ENOENT')throw error;return {path:resolved.relative,exists:false,content:null,sha256:null}}
}

/** @param {string} cwd */
async function ledger(cwd){
  const root=await fs.realpath(cwd);let current=root
  for(const name of ['.oqelira','changes']){
    current=path.join(current,name)
    await fs.mkdir(current,{recursive:false,mode:0o700}).catch(error=>{if(/** @type {NodeJS.ErrnoException} */(error).code!=='EEXIST')throw error})
    const stat=await fs.lstat(current)
    if(stat.isSymbolicLink()||!stat.isDirectory())throw new Error('Invalid change storage')
  }
  return current
}

/** @param {string} cwd @param {string} id @returns {Promise<Change>} */
async function readChange(cwd,id){
  if(typeof id!=='string'||!/^[0-9a-f-]{36}$/.test(id))throw new Error('Invalid change ID')
  const file=path.join(await ledger(cwd),id+'.json'),stat=await fs.lstat(file)
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>100000)throw new Error('Invalid change record')
  /** @type {Change} */ const value=JSON.parse(await fs.readFile(file,'utf8'))
  if(value.id!==id||value.state!=='applied'||typeof value.path!=='string'||!value.before||!value.after)throw new Error('Change is incomplete; inspect the project before continuing')
  return value
}

/** @param {string} cwd @param {string} id @returns {Promise<FileChangeInput>} */
export async function readFileChange(cwd,id){
  const record=await readChange(cwd,id)
  return {change_id:id,path:record.path,expected_sha256:record.after.sha256,content:record.before.content}
}

/** @param {string} cwd @param {FileChangeInput} input @param {boolean} [revert] @param {AbortSignal} [signal] */
export async function applyFileChange(cwd,input,revert=false,signal){
  if(!input||typeof input!=='object'||(input.content!==null&&(typeof input.content!=='string'||input.content.length>10000))||(input.expected_sha256!==null&&(typeof input.expected_sha256!=='string'||!/^[a-f0-9]{64}$/.test(input.expected_sha256))))throw new Error('Use a file snapshot hash and UTF-8 content of at most 10000 characters; null content deletes a file')
  signal?.throwIfAborted()
  const resolved=await target(cwd,input.path),directory=await ledger(cwd)
  const lock=path.join(directory,'.lock');const handle=await fs.open(lock,'wx',0o600).catch(()=>{throw new Error('Another change is active or interrupted; review change storage before retrying')})
  const id=randomUUID(),journal=path.join(directory,id+'.json')
  let temporary
  try{
    if(revert){if(typeof input.change_id!=='string')throw new Error('Revert requires a recorded change ID');const saved=await readChange(cwd,input.change_id);if(saved.path!==resolved.relative||saved.after.sha256!==input.expected_sha256||saved.before.content!==input.content)throw new Error('Revert input does not match the recorded change')}
    const before=await snapshotFile(cwd,input.path)
    if(before.sha256!==input.expected_sha256)throw new Error('File changed since preview; refresh the snapshot before applying')
    if(!before.exists&&input.content===null)throw new Error('File does not exist')
    /** @type {Change} */ const record={id,path:resolved.relative,before,after:{sha256:input.content===null?null:digest(input.content)},state:'prepared'}
    await fs.writeFile(journal,JSON.stringify(record),{flag:'wx',mode:0o600})
    signal?.throwIfAborted()
    await fs.mkdir(path.dirname(resolved.file),{recursive:true})
    if(input.content!==null){temporary=path.join(path.dirname(resolved.file),'.oqelira-'+id+'.tmp');await fs.writeFile(temporary,input.content,{flag:'wx',mode:before.exists?(await fs.stat(resolved.file)).mode&0o777:0o644})}
    if((await snapshotFile(cwd,input.path)).sha256!==before.sha256)throw new Error('File changed while preparing; no change applied')
    signal?.throwIfAborted()
    if(input.content===null)await fs.unlink(resolved.file)
    else if(!before.exists){
      const source=temporary;if(!source)throw new Error('Missing temporary change')
      // COPYFILE_EXCL preserves the stale-write guarantee where hard links are unavailable (notably Windows app sandboxes).
      await fs.copyFile(source,resolved.file,fs.constants.COPYFILE_EXCL);await fs.unlink(source);temporary=undefined
    } else {
      const source=temporary;if(!source)throw new Error('Missing temporary change')
      try{await fs.rename(source,resolved.file)}
      catch(error){
        // Windows can reject replacement renames when a scanner has the destination open. The hash was checked immediately above.
        if(process.platform!=='win32'||/** @type {NodeJS.ErrnoException} */(error).code!=='EPERM')throw error
        await fs.copyFile(source,resolved.file);await fs.unlink(source)
      }
      temporary=undefined
    }
    record.state='applied';await fs.writeFile(journal,JSON.stringify(record),{mode:0o600})
    return JSON.stringify({change_id:id,path:record.path,sha256:record.after.sha256,reverted_change:revert?input.change_id:undefined})
  }finally{if(temporary)await fs.unlink(temporary).catch(()=>{});await handle.close();await fs.unlink(lock).catch(()=>{})}
}

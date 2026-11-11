/** Joins class names, skipping anything falsy. */
export const cx = (...parts) => parts.filter(Boolean).join(' ');

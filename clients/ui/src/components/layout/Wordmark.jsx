import wordmark from '../../assets/logo/flwn-wordmark-navy.svg';

/** The flwn wordmark, as delivered: navy, on a light ground, never altered. Nothing sits beside it. */
export default function Wordmark({ className = '' }) {
  return <img src={wordmark} alt="flwn" className={`h-7 w-auto ${className}`} />;
}

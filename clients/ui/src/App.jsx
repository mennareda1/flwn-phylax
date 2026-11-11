import ReviewPage from './pages/review/ReviewPage.jsx';

/** The app is one screen. `backend` is where the review's data comes from: the demo today, a live connection later. */
export default function App({ backend }) {
  return <ReviewPage backend={backend} />;
}

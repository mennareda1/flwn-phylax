import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

afterEach(() => cleanup());

// jsdom has no layout, no scrolling and no media queries: give the few browser features the app touches a harmless stand-in.
window.matchMedia ??= (query) => ({ matches: false, media: query, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
Element.prototype.scrollIntoView ??= function scrollIntoView() {};

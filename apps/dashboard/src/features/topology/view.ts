import { CANVAS } from "./layout";

/** What part of the canvas the graph shows: a zoom factor and the point at the middle of the view. */
export interface View {
  zoom: number;
  cx: number;
  cy: number;
}

export const MIN_ZOOM = 0.5;
export const MAX_ZOOM = 4;
export const HOME: View = { zoom: 1, cx: CANVAS.width / 2, cy: CANVAS.height / 2 };

const clamp = (value: number, low: number, high: number) => Math.min(high, Math.max(low, value));

/** The visible rectangle, in canvas units (the SVG `viewBox`). */
export function box(v: View): { x: number; y: number; w: number; h: number } {
  const w = CANVAS.width / v.zoom;
  const h = CANVAS.height / v.zoom;
  return { x: v.cx - w / 2, y: v.cy - h / 2, w, h };
}

/** Zoom by `factor` keeping the canvas point (px, py) at the same place on screen. */
export function zoomAt(v: View, factor: number, px: number, py: number): View {
  const zoom = clamp(v.zoom * factor, MIN_ZOOM, MAX_ZOOM);
  const before = box(v);
  const after = box({ ...v, zoom });
  const x = px - (px - before.x) * (after.w / before.w);
  const y = py - (py - before.y) * (after.h / before.h);
  return keepOnCanvas({ zoom, cx: x + after.w / 2, cy: y + after.h / 2 });
}

/** Move the view by a mouse drag of (dx, dy) canvas units: the picture follows the mouse. */
export function panBy(v: View, dx: number, dy: number): View {
  return keepOnCanvas({ ...v, cx: v.cx - dx, cy: v.cy - dy });
}

/** The middle of the view never leaves the canvas, so the graph cannot be lost off screen. */
function keepOnCanvas(v: View): View {
  return { zoom: v.zoom, cx: clamp(v.cx, 0, CANVAS.width), cy: clamp(v.cy, 0, CANVAS.height) };
}

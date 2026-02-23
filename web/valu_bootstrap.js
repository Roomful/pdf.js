/**
 * ============================================================================
 * VALU-SYNC: Real-time PDF Viewer Synchronization for Valu Social
 * ============================================================================
 *
 * This module enables real-time synchronization of PDF viewer state between
 * a presenter and multiple viewers during video chat sessions.
 *
 * ============================================================================
 * FEATURES
 * ============================================================================
 *
 * 1. PAGE SYNC
 *    - Presenter navigates → viewers follow to same page
 *
 * 2. TEXT SELECTION SYNC
 *    - Presenter selects text → viewers see same selection highlighted
 *    - Selection represented as DFS indices (browser-agnostic)
 *    - Clearing selection also syncs
 *
 * 3. ANNOTATION SYNC
 *    - Ink/Draw: Real-time stroke sync (see drawing as it happens)
 *    - FreeText: Text annotations synced as DOM overlays
 *    - Highlight: Both text-based and free-form highlights
 *
 * ============================================================================
 * ARCHITECTURE
 * ============================================================================
 *
 *   ┌─────────────────┐         postMessage          ┌─────────────────┐
 *   │   PRESENTER     │ ──────────────────────────▶  │   PARENT APP    │
 *   │   (pdf.js)      │                              │ (valu-social)   │
 *   │                 │  ◀────────────────────────── │                 │
 *   └─────────────────┘         postMessage          └────────┬────────┘
 *                                                             │
 *                                                    forwards to viewers
 *                                                             │
 *                                                             ▼
 *                                                    ┌─────────────────┐
 *                                                    │    VIEWERS      │
 *                                                    │    (pdf.js)     │
 *                                                    └─────────────────┘
 *
 * ============================================================================
 * MESSAGE FORMAT
 * ============================================================================
 *
 * Outgoing (to parent):
 * {
 *   source: "valu-social-pdf-viewer",
 *   payload: {
 *     message: "syncFullState",
 *     data: {
 *       page: number,
 *       anchorNodeIndex: number,    // Text selection (DFS index)
 *       focusNodeIndex: number,
 *       anchorOffset: number,
 *       focusOffset: number,
 *       length: number,             // 0 = no selection
 *       annotations: Array,         // Serialized annotations
 *       annotationsHash: string,
 *       event: string,              // What triggered this sync (see SYNC EVENTS)
 *       activityAction: string|null // Presenter gesture (see SYNC EVENTS), null if none
 *     }
 *   }
 * }
 *
 * Incoming (from parent):
 * {
 *   source: "valu-social-app",
 *   payload: {
 *     message: "syncFullState",
 *     data: { ... same structure ... }
 *   }
 * }
 *
 * ============================================================================
 * SYNC EVENTS (rawData.event values)
 * ============================================================================
 *
 * - "documentLoaded"       Initial sync when PDF fully loads
 * - "pageChanged"          User navigated to different page
 * - "textSelected"         User selected text
 * - "textSelectionCleared" User cleared text selection
 * - "annotationsChanged"   Annotation created/modified/deleted (debounced)
 * - "drawingStarted"       Presenter began an ink/draw stroke
 * - "drawingEnded"         Presenter finished an ink/draw stroke (carries new annotation)
 * - "highlightStarted"     Presenter began a free highlight gesture
 * - "highlightEnded"       Presenter finished a free highlight (carries new annotation)
 * - "freeTextStarted"      Presenter opened a new text annotation box
 * - "freeTextEnded"        Presenter committed a text annotation
 *
 * ============================================================================
 * ANNOTATION RENDERING STRATEGIES
 * ============================================================================
 *
 * Different annotation types require different rendering approaches on viewer:
 *
 * | Type        | Rendering Method | Why?                                    |
 * |-------------|------------------|-----------------------------------------|
 * | In-progress | SVG overlay      | Not in storage yet, need real-time view |
 * | FreeText    | DOM overlay      | Editor layer triggers mode switch bugs  |
 * | Ink/Draw    | Editor layer     | Proper SVG rendering via pdf.js         |
 * | Highlight   | Editor layer     | Proper SVG rendering via pdf.js         |
 *
 * ============================================================================
 * GLOBAL STATE (on window object)
 * ============================================================================
 *
 * - resourcePageStartNumber      Initial page from sync
 * - resourcePageCurrentSelection Current selection data for re-application
 * - resourcePageChanged          Callback for page change events
 * - selectionTrigger             Selection state flag
 * - isApplyingRemoteState        Echo prevention (don't sync while applying)
 * - currentInProgressDrawing     Current drawing snapshot for sync
 *
 * ============================================================================
 * RELATED PDF.JS MODIFICATIONS
 * ============================================================================
 *
 * Search for "VALU-SYNC" in these files to find all customizations:
 *
 * src/display/editor/tools.js
 *   - Modified addCommands() to force event dispatch for DRAW_STEP
 *   - Passes inProgressDrawing through to eventBus
 *
 * src/display/editor/draw.js
 *   - Captures drawing snapshot in _endDraw() for real-time sync
 *   - Builds inProgressDrawing object with SVG path, color, etc.
 *   - Dispatches "annotationactivity" events for drawingStarted/drawingEnded
 *
 * src/display/editor/highlight.js
 *   - Dispatches "annotationactivity" events for highlightStarted/highlightEnded
 *
 * src/display/editor/annotation_editor_layer.js
 *   - Passes uiManager to HighlightEditor.startHighlighting() for event dispatch
 *
 * src/display/editor/freetext.js
 *   - Dispatches "annotationactivity" events for freeTextStarted/freeTextEnded
 *
 * src/display/editor/drawers/inkdraw.js
 *   - Added getSnapshotData() for non-destructive state access
 *   - Unlike getOutlines(), doesn't reset internal state
 *
 * src/display/editor/editor.js
 *   - Added null check in get comment() getter
 *   - Prevents crash when synced editors haven't initialized #comment
 *
 * web/pdf_node_utils.js
 *   - DFS functions skip elements with data-valu-sync-ignore attribute
 *   - Prevents FreeText overlay text nodes from breaking selection indices
 *
 * ============================================================================
 * KNOWN LIMITATIONS
 * ============================================================================
 *
 * - Stamp/Image annotations not synced (not implemented)
 * - Signature annotations not synced (not implemented)
 * - Annotation editing (resize, move) not synced in real-time
 * - Comments/replies on annotations not synced
 *
 * ============================================================================
 */

import {
  findSelectionIndicesDFS,
  restoreSelectionFromIndices,
} from "./pdf_node_utils.js";

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Standard debounce helper - delays function execution until after wait ms
 * have elapsed since the last call. Used for annotation sync to avoid
 * flooding the parent with messages during rapid changes (like drawing).
 */
function debounce(func, wait) {
  let timeout;
  return function (...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}

/**
 * Recursively converts typed arrays (Float32Array, etc.) to regular arrays.
 * Required because pdf.js uses typed arrays internally, but postMessage
 * serialization and our sync protocol need plain JSON-compatible objects.
 */
function makeJsonSafe(obj) {
  if (obj === null || obj === undefined) {
    return obj;
  }
  if (ArrayBuffer.isView(obj)) {
    return Array.from(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map(makeJsonSafe);
  }
  if (typeof obj === "object") {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = makeJsonSafe(value);
    }
    return result;
  }
  return obj;
}

// ============================================================================
// ANNOTATION SERIALIZATION
// ============================================================================

/**
 * Collects all annotations from pdf.js annotation storage and converts them
 * to a JSON-safe format for transmission.
 *
 * @param inProgressDrawing - Optional in-progress drawing data (stroke not yet
 *                            committed to storage, captured during drawing)
 * @returns {annotations, hash} - Array of serialized annotations and a hash
 */
function getSerializedAnnotations(inProgressDrawing = null) {
  const annotations = [];
  let hash = "";

  if (typeof PDFViewerApplication !== "undefined" && PDFViewerApplication.pdfDocument) {
    try {
      const serializable = PDFViewerApplication.pdfDocument.annotationStorage.serializable;
      if (serializable?.map) {
        for (const [id, data] of serializable.map) {
          const safeData = makeJsonSafe(data);
          annotations.push({ id, ...safeData });
        }
        hash = serializable.hash || "";
      }
    } catch (e) {
      // Some editors may be in partial state and fail to serialize
      // (e.g., highlight editors with null boxes during creation)
    }
  }

  // In-progress drawings aren't in storage yet (only committed after stroke ends),
  // so we include them separately for real-time sync during drawing
  if (inProgressDrawing) {
    const safeDrawing = makeJsonSafe(inProgressDrawing);
    annotations.push({ id: "in-progress-drawing", ...safeDrawing });
  }

  return { annotations, hash };
}

// ============================================================================
// ANNOTATION RENDERING (VIEWER SIDE)
// ============================================================================

/**
 * Renders an in-progress drawing as an SVG overlay on the viewer side.
 * This shows the drawing while the presenter is still drawing (before commit).
 *
 * Why SVG overlay instead of using pdf.js drawing layer?
 * - The drawing layer is tightly coupled to the editor state machine
 * - We need a lightweight, non-interactive visual representation
 * - SVG with viewBox 10000x10000 matches pdf.js internal coordinate space
 */
function renderInProgressDrawing(pageView, drawing) {
  if (!drawing || !drawing.svgPath) {
    return;
  }

  const canvasWrapper = pageView.div.querySelector(".canvasWrapper");
  if (!canvasWrapper) return;

  // Remove any existing overlay first (we're replacing, not accumulating)
  const existingOverlay = canvasWrapper.querySelector(".in-progress-drawing-overlay");
  if (existingOverlay) {
    existingOverlay.remove();
  }

  // Create SVG with same coordinate space as pdf.js ink drawing (10000x10000)
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.classList.add("in-progress-drawing-overlay");
  svg.setAttribute("viewBox", "0 0 10000 10000");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.style.cssText = `
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: 5;
  `;

  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", drawing.svgPath);
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", drawing.color || "#000000");
  // Thickness needs scaling for the 10000x10000 viewBox (empirically ~15x works)
  const scaledThickness = (drawing.thickness || 1) * 15;
  path.setAttribute("stroke-width", scaledThickness);
  path.setAttribute("stroke-opacity", drawing.opacity || 1);
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");

  svg.appendChild(path);
  canvasWrapper.appendChild(svg);
}

/**
 * Removes all in-progress drawing overlays from all pages.
 */
function clearInProgressDrawings() {
  const overlays = document.querySelectorAll(".canvasWrapper .in-progress-drawing-overlay");
  overlays.forEach(overlay => overlay.remove());
}

/**
 * Renders a FreeText annotation as a simple DOM overlay on the viewer side.
 *
 * Why DOM overlay instead of using pdf.js FreeText editor?
 * - Using the editor layer triggers pdf.js mode switching (FREETEXT mode)
 * - Mode switching enables text selection interception for highlighting
 * - This breaks normal text selection on the viewer side
 * - Simple DOM overlay avoids all that complexity
 *
 * The styling matches pdf.js FreeText (.freeTextEditor .internal) for consistency.
 */
function renderFreeTextOverlay(pageView, annotation) {
  if (!annotation || !annotation.value) {
    return;
  }

  const canvasWrapper = pageView.div.querySelector(".canvasWrapper");
  if (!canvasWrapper) return;

  const rect = annotation.rect;
  if (!rect || rect.length < 4) return;

  // Calculate scale factors to convert PDF coordinates to screen pixels
  const viewport = pageView.viewport;
  const pageWidth = viewport.width;
  const pageHeight = viewport.height;
  const [pdfPageWidth, pdfPageHeight] = [viewport.viewBox[2], viewport.viewBox[3]];

  const scaleX = pageWidth / pdfPageWidth;
  const scaleY = pageHeight / pdfPageHeight;

  // PDF uses bottom-left origin, screen uses top-left origin
  const x = Math.min(rect[0], rect[2]) * scaleX;
  const y = pageHeight - Math.max(rect[1], rect[3]) * scaleY;

  // Create container - matches pdf.js styling (width: auto, no fixed dimensions)
  const overlay = document.createElement("div");
  overlay.className = "valu-freetext-overlay";
  overlay.dataset.annotationId = annotation.id || "";
  // This attribute tells pdf_node_utils.js DFS to skip this element,
  // so our text nodes don't mess up selection index counting
  overlay.dataset.valuSyncIgnore = "true";
  overlay.style.cssText = `
    position: absolute;
    left: ${x}px;
    top: ${y}px;
    pointer-events: none;
    z-index: 5;
    padding: ${2 * scaleX}px;
    box-sizing: border-box;
  `;

  // Create text content - styling matches .freeTextEditor .internal
  const textDiv = document.createElement("div");
  const fontSize = annotation.fontSize || 10;
  const color = annotation.color
    ? `rgb(${annotation.color[0]}, ${annotation.color[1]}, ${annotation.color[2]})`
    : "#000000";

  textDiv.style.cssText = `
    font: ${fontSize * scaleX}px sans-serif;
    color: ${color};
    white-space: nowrap;
    line-height: 1.35;
  `;

  // Handle multiline text by creating divs like pdf.js does internally
  const lines = (annotation.value || "").split("\n");
  for (const line of lines) {
    const lineDiv = document.createElement("div");
    lineDiv.appendChild(line ? document.createTextNode(line) : document.createElement("br"));
    textDiv.appendChild(lineDiv);
  }

  overlay.appendChild(textDiv);
  canvasWrapper.appendChild(overlay);
}

/**
 * Removes all FreeText overlays from all pages.
 */
function clearFreeTextOverlays() {
  const overlays = document.querySelectorAll(".canvasWrapper .valu-freetext-overlay");
  overlays.forEach(overlay => overlay.remove());
}

// ============================================================================
// ANNOTATION APPLICATION (VIEWER SIDE)
// ============================================================================

// pdf.js annotation editor type constants (from shared/util.js)
const AnnotationEditorType = {
  NONE: 0,
  FREETEXT: 3,
  HIGHLIGHT: 9,
  INK: 15,
};

/**
 * Applies annotations received from the presenter to the viewer's PDF.
 * Uses "replace" strategy: clears all existing annotations, then applies new ones.
 *
 * Different annotation types are handled differently:
 * - In-progress drawings: Rendered as SVG overlays (temporary, during drawing)
 * - FreeText: Rendered as DOM overlays (avoids mode switching issues)
 * - Ink/Highlight: Rendered via pdf.js editor layer (proper rendering)
 *
 * @param annotations - Array of serialized annotations from presenter
 * @param root - Window object (for accessing global state)
 */
async function applyAnnotations(annotations, root) {
  if (typeof PDFViewerApplication === "undefined") return;

  const pdfDoc = PDFViewerApplication.pdfDocument;
  const pdfViewer = PDFViewerApplication.pdfViewer;
  if (!pdfDoc || !pdfViewer) return;

  // Prevent our changes from triggering sync back to presenter (echo prevention)
  root.isApplyingRemoteState = true;

  try {
    // Step 1: Clear all existing overlays and editor elements
    clearInProgressDrawings();
    clearFreeTextOverlays();

    // Remove DOM elements for editor annotations from all pages
    // We can't access private #uiManager, so we remove elements directly
    const pageCount = pdfViewer.pagesCount;
    for (let i = 0; i < pageCount; i++) {
      const pageView = pdfViewer.getPageView(i);

      // Remove SVG elements from DrawLayer (ink drawings and highlights)
      const canvasWrapper = pageView?.div?.querySelector('.canvasWrapper');
      if (canvasWrapper) {
        const drawLayerSvgs = canvasWrapper.querySelectorAll('svg.draw, svg.highlight');
        drawLayerSvgs.forEach(svg => svg.remove());
      }

      // Remove editor divs from annotation editor layer
      // (FreeText uses overlay, so we skip .freeTextEditor)
      if (pageView?.annotationEditorLayer?.annotationEditorLayer) {
        const layer = pageView.annotationEditorLayer.annotationEditorLayer;
        const editorDivs = layer.div?.querySelectorAll('.inkEditor, .highlightEditor, .stampEditor');
        editorDivs?.forEach(div => div.remove());
      }
    }

    // Step 2: Clear annotation storage (after DOM removal, since remove() may commit)
    const storage = pdfDoc.annotationStorage;
    const allEntries = [...storage];
    const keysToRemove = [];
    for (const [key, value] of allEntries) {
      if (value && (value.annotationType !== undefined || value.annotationEditorType !== undefined)) {
        keysToRemove.push(key);
      }
    }
    for (const key of keysToRemove) {
      storage.remove(key);
    }

    if (!annotations || annotations.length === 0) {
      return;
    }

    // Step 3: Separate annotations by type for different rendering strategies
    const inProgressDrawings = annotations.filter(a => a.isInProgress);
    const freeTextAnnotations = annotations.filter(a => {
      const type = Number(a.annotationType ?? a.annotationEditorType);
      return type === AnnotationEditorType.FREETEXT && !a.isInProgress;
    });
    const editorAnnotations = annotations.filter(a => {
      const type = Number(a.annotationType ?? a.annotationEditorType);
      return type !== AnnotationEditorType.FREETEXT && !a.isInProgress;
    });

    // Step 4: Render in-progress drawings as SVG overlays
    for (const drawing of inProgressDrawings) {
      const pageView = pdfViewer.getPageView(drawing.pageIndex ?? 0);
      if (pageView) {
        renderInProgressDrawing(pageView, drawing);
      }
    }

    // Step 5: Render FreeText as DOM overlays (avoids mode switching)
    for (const annotation of freeTextAnnotations) {
      const pageView = pdfViewer.getPageView(annotation.pageIndex ?? 0);
      if (pageView) {
        renderFreeTextOverlay(pageView, annotation);
      }
    }

    // Step 6: Render Ink/Highlight via editor layer (proper pdf.js rendering)
    const annotationsByPage = new Map();
    for (const annotation of editorAnnotations) {
      const pageIndex = annotation.pageIndex ?? 0;
      if (!annotationsByPage.has(pageIndex)) {
        annotationsByPage.set(pageIndex, []);
      }
      annotationsByPage.get(pageIndex).push(annotation);
    }

    for (const [pageIndex, pageAnnotations] of annotationsByPage) {
      const pageView = pdfViewer.getPageView(pageIndex);
      if (!pageView) continue;

      const layer = pageView.annotationEditorLayer?.annotationEditorLayer;
      if (!layer) continue;

      for (const annotation of pageAnnotations) {
        try {
          const editorType = annotation.annotationType ?? annotation.annotationEditorType;
          const isHighlight = Number(editorType) === AnnotationEditorType.HIGHLIGHT;

          // annotationElementId prevents addUndoableEditor() call,
          // which would show undo UI and trigger selection popups
          const syncedId = annotation.id || `synced-${Date.now()}-${Math.random()}`;
          const annotationData = {
            ...annotation,
            annotationElementId: syncedId,
          };

          // Free highlights (drawn, not text-based) use outlines.points format
          // when serialized, but deserialize expects inkLists format
          if (isHighlight && !annotation.quadPoints && annotation.outlines?.points) {
            annotationData.inkLists = annotation.outlines.points;
          }

          const editor = await layer.deserialize(annotationData);
          if (editor) {
            // _initialData is required to prevent crashes in #hasElementChanged
            // when serialize() is called (e.g., during mode switches)
            const rect = annotation.rect || [0, 0, 0, 0];
            editor._initialData = {
              color: annotation.color || [0, 0, 0],
              thickness: annotation.thickness,
              opacity: annotation.opacity,
              pageIndex: annotation.pageIndex,
              position: [rect[0], rect[1]],
            };

            layer.add(editor);
          }
        } catch (e) {
          console.warn("Failed to deserialize annotation:", e);
        }
      }
    }

  } finally {
    root.isApplyingRemoteState = false;
  }
}

// ============================================================================
// MAIN BOOTSTRAP FUNCTION
// ============================================================================

/**
 * Main entry point for Valu Social PDF viewer synchronization.
 *
 * Sets up:
 * - Global state variables on window object
 * - Outgoing sync (presenter -> parent app -> viewers)
 * - Incoming sync (parent app -> this viewer)
 * - Event hooks for page changes, text selection, annotations
 *
 * @returns URL for the PDF resource (for loading)
 */
function valuBootstrap() {
  let url = null;
  let root = typeof window === "object" ? window : undefined;
  if (root !== undefined) {
    try {
      // Global state variables exposed on window for external access
      root.resourcePageStartNumber = undefined;      // Initial page from sync
      root.resourcePageCurrentSelection = undefined; // Current text selection data
      root.resourcePageChanged = null;               // Callback set later
      root.selectionTrigger = false;                 // Selection state flag
      root.isApplyingRemoteState = false;            // Echo prevention flag
      root.currentInProgressDrawing = null;          // In-progress drawing data

      // Parse URL parameters for resource identification
      let _urlParams = new URLSearchParams(root.location.search);

      let videoChatId = _urlParams.get("videoChat");
      let roomId = _urlParams.get("room");
      let propId = _urlParams.get("prop");
      let resourceId = _urlParams.get("resource") || "";
      let sessionId = _urlParams.get("session") || "";

      url = "https://api.roomful.net/api/v0/resource/url/" + resourceId + "?sessionId=" + sessionId;

      // ========================================================================
      // SYNC STATE - This is what gets sent to parent on every sync
      // ========================================================================
      let rawData = {
        // Page state
        page: 1,
        // Text selection state (DFS indices for cross-browser restoration)
        anchorNodeIndex: -1,
        focusNodeIndex: -1,
        anchorOffset: 0,
        focusOffset: 0,
        length: 0,
        // Annotations (populated fresh on each sync)
        annotations: [],
        annotationsHash: "",
        // Debug info - which event triggered this sync
        event: null,
      };

      // ========================================================================
      // OUTGOING SYNC - Send state to parent window
      // ========================================================================

      /**
       * Sends current state to parent window.
       * Parent app decides who is presenting and forwards to viewers.
       */
      let submitSyncState = function (event, activityAction = null) {
        // Always include fresh annotation data (with in-progress drawing if any)
        const { annotations, hash } = getSerializedAnnotations(root.currentInProgressDrawing);
        rawData.annotations = annotations;
        rawData.annotationsHash = hash;
        rawData.event = event;

        // activityAction is spread fresh per-message, NOT stored in rawData,
        // so it never leaks into subsequent non-activity syncs.
        window.parent.postMessage(
          {
            source: "valu-social-pdf-viewer",
            payload: {
              message: "syncFullState",
              data: { ...rawData, activityAction },
            },
          },
          "*"
        );
      };

      // Tracks the current presenter activity so intermediate annotationsChanged
      // messages carry the same context (e.g. "drawingStarted" while drawing).
      // Set on *Started, reset to null after sending *Ended.
      let lastActivityAction = null;

      // Debounced version for annotation changes (300ms delay)
      // Prevents flooding during rapid changes like drawing strokes
      const debouncedAnnotationSync = debounce(() => {
        if (root.isApplyingRemoteState) return;
        submitSyncState("annotationsChanged", lastActivityAction);
      }, 300);

      // ========================================================================
      // INCOMING SYNC - Receive state from parent window
      // ========================================================================

      window.addEventListener("message", event => {
        // Only accept messages from our parent app
        if (event.data.source !== "valu-social-app") return;
        if (event.data.payload.message !== "syncFullState") return;

        const data = event.data.payload.data;

        // Apply page change
        if (data.page && data.page > 0) {
          root.resourcePageStartNumber = data.page;
          PDFViewerApplication.page = data.page;
        }

        // Apply text selection (or clear it)
        if (data.length > 0) {
          // Store selection data for potential re-application
          root.resourcePageCurrentSelection = {
            page: data.page,
            anchorNodeIndex: data.anchorNodeIndex,
            focusNodeIndex: data.focusNodeIndex,
            anchorOffset: data.anchorOffset,
            focusOffset: data.focusOffset,
            length: data.length,
          };
          root.onHighlightReceive(root.resourcePageCurrentSelection);
        } else if (data.length === 0 && root.resourcePageCurrentSelection) {
          // Presenter cleared their selection - clear ours too
          root.resourcePageCurrentSelection = undefined;
          // Clear browser selection
          const sel = root.document.getSelection();
          if (sel) {
            sel.removeAllRanges();
          }
          // Also clear any visual highlight spans
          const $pdfViewer = root.document.querySelector(".pdfViewer");
          if ($pdfViewer) {
            root.clearAllSelections(null, $pdfViewer);
          }
        }

        // Apply annotations (replace mode)
        if (data.annotations) {
          applyAnnotations(data.annotations, root);
        }
      });

      // ========================================================================
      // TEXT SELECTION HELPERS
      // ========================================================================

      /**
       * Clears all visual text selection highlights (span.highlight elements).
       * These are created by restoreSelectionFromIndices for visual feedback.
       *
       * The cleanup process:
       * 1. Extract text content from highlight span
       * 2. Insert it as plain text after the span
       * 3. Normalize parent to merge adjacent text nodes
       * 4. Remove the now-empty span
       */
      root.clearAllSelections = function (callback, $element = root.document) {
        root.selectionTrigger = false;
        let $elements = [...$element.querySelectorAll("span.highlight")];
        for (let i = 0; i < $elements.length; i++) {
          let highlightHTML = $elements[i].innerText;
          $elements[i].innerText = "";
          $elements[i].insertAdjacentText("afterend", highlightHTML);
          $elements[i].parentNode.normalize();
          $elements[i].remove();
        }
        if (callback && typeof callback === "function") {
          // Small delay to ensure DOM is settled before callback
          setTimeout(callback, 20);
        }
      };

      /**
       * Receives text selection data from presenter and applies it locally.
       * Clears existing selection first, then restores from DFS indices.
       */
      root.onHighlightReceive = function (data) {
        let $pdfViewer = root.document.querySelector(".pdfViewer");
        let $element = root.document.querySelector('.pdfViewer .page[data-page-number="' + data.page + '"]');

        if ($pdfViewer && $element) {
          root.clearAllSelections(function () {
            restoreSelectionFromIndices($element, data);
          }, $pdfViewer);
        }
      };

      // ========================================================================
      // DOM READY - Set up event listeners
      // ========================================================================

      root.document.addEventListener("DOMContentLoaded", function () {

        /**
         * Handles text selection events on presenter side.
         * Captures selection using DFS indices (browser-agnostic representation)
         * and syncs to viewers.
         */
        let OnSelectionTextEvent = function ($element) {
          if ($element === undefined) {
            $element = root.document.querySelector(".pdfViewer .page");
          }
          let page = parseInt($element.getAttribute("data-page-number") || 0);

          let selection = root.document.getSelection();
          let length = selection.toString().length;

          // Handle selection clear
          if (length === 0) {
            if (rawData.length > 0) {
              // Had selection before, now cleared - sync the clear
              rawData = {
                ...rawData,
                anchorNodeIndex: -1,
                focusNodeIndex: -1,
                anchorOffset: 0,
                focusOffset: 0,
                length: 0,
              };
              submitSyncState("textSelectionCleared");
            }
            return;
          }

          // Capture selection as DFS indices (works across browsers)
          let dfs = findSelectionIndicesDFS($element);

          rawData = {
            ...rawData,
            videochatId: videoChatId,
            roomId: roomId,
            propId: propId,
            resourceId: resourceId,
            page: page,
            anchorNodeIndex: dfs.anchorNodeIndex,
            focusNodeIndex: dfs.focusNodeIndex,
            anchorOffset: dfs.anchorOffset,
            focusOffset: dfs.focusOffset,
            length: length,
          };
          submitSyncState("textSelected");
        };

        // Capture text selection on mouse up (left click only)
        root.addEventListener("mouseup", function (e) {
          if (e.button === 0) {
            let $element = e.target.closest(".pdfViewer .page");
            if ($element) {
              OnSelectionTextEvent($element);
            }
          }
        });

        // Also listen for selection clear (clicking outside, etc.)
        root.document.addEventListener("selectionchange", function () {
          let selection = root.document.getSelection();
          let length = selection.toString().length;

          if (length === 0 && rawData.length > 0) {
            rawData = {
              ...rawData,
              anchorNodeIndex: -1,
              focusNodeIndex: -1,
              anchorOffset: 0,
              focusOffset: 0,
              length: 0,
            };
            submitSyncState("textSelectionCleared");
          }
        });

        // ======================================================================
        // PAGE CHANGE HANDLER
        // ======================================================================

        /**
         * Called externally when page changes (e.g., from pdf.js page navigation).
         * Syncs the new page number to viewers.
         */
        root.resourcePageChanged = function (page) {
          if (page === undefined || page < 0) {
            page = 0;
          }

          rawData = {
            ...rawData,
            videochatId: videoChatId,
            roomId: roomId,
            propId: propId,
            resourceId: resourceId,
            page: page,
          };
          submitSyncState("pageChanged");
        };

        // ======================================================================
        // PDF.JS EVENT HOOKS
        // ======================================================================

        /**
         * Hooks into pdf.js events when PDFViewerApplication is ready.
         * Uses polling because PDFViewerApplication may not be available immediately.
         */
        const hookAnnotationEvents = () => {
          if (typeof PDFViewerApplication !== "undefined" && PDFViewerApplication.eventBus) {

            // Hook annotation editor changes (drawings, highlights, text)
            PDFViewerApplication.eventBus.on("annotationeditorstateschanged", event => {
              if (root.isApplyingRemoteState) return; // Don't echo back received state
              // Capture in-progress drawing for real-time sync during drawing
              root.currentInProgressDrawing = event.inProgressDrawing || null;
              debouncedAnnotationSync();
            });

            // VALU-SYNC: Forward presenter activity events as full state syncs.
            // Using submitSyncState (not a separate message type) ensures late-joining
            // viewers receive the complete current state alongside the activity signal.
            // The rawData.event field tells the parent app what triggered this sync.
            PDFViewerApplication.eventBus.on("annotationactivity", ({ activityType }) => {
              if (root.isApplyingRemoteState) return;
              // Persist the activity so intermediate annotationsChanged messages
              // carry the same context. Reset to null after *Ended so subsequent
              // idle messages don't carry stale activity state.
              lastActivityAction = activityType;
              submitSyncState("annotationsChanged", lastActivityAction);
              if (activityType.endsWith("Ended")) {
                lastActivityAction = null;
              }
            });

            // Send initial sync when document is fully loaded
            // This ensures pre-existing annotations and current page are synced
            // to viewers who join mid-session
            PDFViewerApplication.eventBus.on("pagesloaded", () => {
              rawData.page = PDFViewerApplication.page || 1;
              submitSyncState("documentLoaded");
            });

          } else {
            // PDFViewerApplication not ready yet, retry in 100ms
            setTimeout(hookAnnotationEvents, 100);
          }
        };

        // Start polling for PDFViewerApplication
        hookAnnotationEvents();
      });
    } catch (e) {
      console.warn(e);
    }
  }

  return url;
}

export { valuBootstrap };

import {
  findSelectionIndicesDFS,
  restoreSelectionFromIndices,
} from "./pdf_node_utils.js";

function valuBootstrap() {
  let url = null;
  let root = typeof window === "object" ? window : undefined;
  if (root !== undefined) {
    try {
      root.resourcePageStartNumber = undefined;
      root.resourcePageCurrentSelection = undefined;
      root.resourcePageChanged = null;
      root.selectionTrigger = false;

      let _urlParams = new URLSearchParams(root.location.search);

      let videoChatId = _urlParams.get("videoChat");
      let roomId = _urlParams.get("room");
      let propId = _urlParams.get("prop");
      let resourceId = _urlParams.get("resource");
      let isPresenting = _urlParams.get("isPresenting") || false;
      let sessionId = _urlParams.get("session");

      url = "https://api.roomful.net/api/v0/resource/url/" + resourceId + "?sessionId=" + sessionId;

      let submitMessageWithData = function(message) {
        if (!isPresenting) return;

        window.parent.postMessage(
          {
            source: 'valu-social-pdf-viewer',
            payload: {
              message,
              data: rawData
            },
          },
          '*'
        );
      }

      let rawData = {
        page: 1,
        anchorNodeIndex: -1,
        focusNodeIndex: -1,
        anchorOffset: 0,
        focusOffset: 0,
        length: 0,
      };

      window.addEventListener("message", (event) => {
        if (event.data.source !== 'valu-social-app') return;

        if (event.data.payload.message === 'resourcePageChanged') {
          let _page = event.data.payload.data.page;
          root.resourcePageStartNumber = _page;

          PDFViewerApplication.page = _page;
        } else if (event.data.payload.message === 'pdfTextSelected') {
          let _page = event.data.payload.data.page;
          let _anchorNodeIndex = event.data.payload.data.anchorNodeIndex;
          let _focusNodeIndex = event.data.payload.data.focusNodeIndex;
          let _anchorOffset = event.data.payload.data.anchorOffset;
          let _focusOffset = event.data.payload.data.focusOffset;
          let _length = event.data.payload.data.length;

          root.resourcePageStartNumber = _page;
          root.resourcePageCurrentSelection = {
            page: _page,
            anchorNodeIndex: _anchorNodeIndex,
            focusNodeIndex: _focusNodeIndex,
            anchorOffset: _anchorOffset,
            focusOffset: _focusOffset,
            length: _length,
          };

          root.onHighlightReceive(root.resourcePageCurrentSelection);
        }
      });

      root.clearAllSelections = function(callback, $element = root.document) {
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
          setTimeout(callback, 20);
        }
      };

      root.onHighlightReceive = function(data) {
        let $pdfViewer = root.document.querySelector(".pdfViewer");
        let $element = root.document.querySelector(".pdfViewer .page[data-page-number=\"" + data.page + "\"]");

        if ($pdfViewer && $element) {
          root.clearAllSelections(function() {
            restoreSelectionFromIndices($element, data);
          }, $pdfViewer);
        }
      };

      root.document.addEventListener("DOMContentLoaded", function() {
        let OnSelectionTextEvent = function($element) {
          if ($element === undefined) {
            $element = root.document.querySelector(".pdfViewer .page");
          }
          let page = parseInt($element.getAttribute("data-page-number") || 0);

          let selection = root.document.getSelection();
          let length = selection.toString().length;

          if (Math.abs(length) === 0) {
            return;
          }

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
          submitMessageWithData('pdfTextSelected');
        };

        root.addEventListener("mouseup", function (e) {
          if (e.button === 0) {
            let $element = e.target.closest(".pdfViewer .page");
            if ($element) {
              OnSelectionTextEvent($element);
            }
          }
        });

        root.resourcePageChanged = function(page) {
          if (page === undefined || page < 0) {
            page = 0;
          }

          rawData = {
            ...rawData,
            videochatId: videoChatId,
            roomId: roomId,
            propId: propId,
            resourceId: resourceId,
            page: page
          };
          submitMessageWithData('resourcePageChanged');
        };
      });
    } catch (e) {
      console.warn(e);
    }
  }

  return url;
}

export { valuBootstrap };

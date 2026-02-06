function findSelectionIndicesDFS($parent) {
  const sel = $parent.getRootNode().getSelection();
  if (!sel || sel.rangeCount === 0) {
    return {
      anchorNodeIndex: -1,
      anchorOffset: 0,
      focusNodeIndex: -1,
      focusOffset: 0
    };
  }

  const range = sel.getRangeAt(0);

  // helpers
  function firstTextNode(node) {
    if (!node) return null;
    if (node.nodeType === Node.TEXT_NODE) return node;
    for (let c of node.childNodes) {
      const t = firstTextNode(c);
      if (t) return t;
    }
    return null;
  }

  function lastTextNode(node) {
    if (!node) return null;
    if (node.nodeType === Node.TEXT_NODE) return node;
    for (let i = node.childNodes.length - 1; i >= 0; i--) {
      const t = lastTextNode(node.childNodes[i]);
      if (t) return t;
    }
    return null;
  }

  function resolveToClosestTextNode(container, offset, isStart) {
    if (!container) return null;

    if (container.nodeType === Node.TEXT_NODE) {
      return { node: container, offset: Math.min(offset, container.textContent.length) };
    }

    const children = container.childNodes;
    const childCount = children.length;

    if (childCount === 0) return null;

    // Start: search forward from offset
    if (isStart) {
      for (let i = offset; i < childCount; i++) {
        const t = firstTextNode(children[i]);
        if (t) return { node: t, offset: 0 };
      }
      // no text node after offset → pick last text node before offset
      for (let i = offset - 1; i >= 0; i--) {
        const t = lastTextNode(children[i]);
        if (t) return { node: t, offset: t.textContent.length };
      }
    } else {
      // End: search backward from offset-1
      for (let i = offset - 1; i >= 0; i--) {
        const t = lastTextNode(children[i]);
        if (t) return { node: t, offset: t.textContent.length };
      }
      // no text node before offset → pick first text node after offset
      for (let i = offset; i < childCount; i++) {
        const t = firstTextNode(children[i]);
        if (t) return { node: t, offset: 0 };
      }
    }

    // No text node found inside container → return null
    return null;
  }

  function fallbackResolve($parent, isStart) {
    let node = null;

    function dfs(n) {
      if (!n || node) return;
      if (n.nodeType === Node.TEXT_NODE) {
        node = n;
        return;
      }
      for (let c of n.childNodes) dfs(c);
    }

    if (isStart) {
      // first text node in $parent subtree
      dfs($parent);
      if (node) return { node, offset: 0 };
    } else {
      // last text node in $parent subtree
      function dfsLast(n) {
        if (!n || node) return;
        for (let i = n.childNodes.length - 1; i >= 0; i--) dfsLast(n.childNodes[i]);
        if (n.nodeType === Node.TEXT_NODE && !node) node = n;
      }
      dfsLast($parent);
      if (node) return { node, offset: node.textContent.length };
    }

    return null;
  }

  let startResolved = resolveToClosestTextNode(range.startContainer, range.startOffset, true);
  let endResolved   = resolveToClosestTextNode(range.endContainer, range.endOffset, false);

  // usage:
  if (!startResolved) startResolved = fallbackResolve($parent, true);
  if (!endResolved)   endResolved   = fallbackResolve($parent, false);

  if (!startResolved || !endResolved) {
    return {
      anchorNodeIndex: -1,
      anchorOffset: 0,
      focusNodeIndex: -1,
      focusOffset: 0
    };
  }

  let anchorNodeIndex = -1;
  let focusNodeIndex  = -1;
  let index = 0;

  function dfs(node) {
    if (!node) return;
    if (anchorNodeIndex !== -1 && focusNodeIndex !== -1) return;

    // VALU-SYNC: Skip elements marked with data-valu-sync-ignore attribute.
    //
    // Problem: FreeText overlays contain text nodes that would be counted
    // in the DFS traversal, throwing off selection indices between presenter
    // and viewer (presenter has no overlays, viewer has them).
    //
    // Solution: Mark overlay elements with data-valu-sync-ignore="true"
    // and skip them entirely during traversal.
    if (node.nodeType === Node.ELEMENT_NODE && node.dataset?.valuSyncIgnore) {
      return;
    }

    if (node.nodeType === Node.TEXT_NODE) {
      if (node === startResolved.node) anchorNodeIndex = index;
      if (node === endResolved.node)   focusNodeIndex  = index;
      index++;
      return;
    }

    for (let c of node.childNodes) dfs(c);
  }

  dfs($parent);

  // normalize order in case of reverse selection
  if (
    anchorNodeIndex > focusNodeIndex ||
    (anchorNodeIndex === focusNodeIndex && startResolved.offset > endResolved.offset)
  ) {
    [anchorNodeIndex, focusNodeIndex] = [focusNodeIndex, anchorNodeIndex];
    [startResolved.offset, endResolved.offset] = [endResolved.offset, startResolved.offset];
  }

  return {
    anchorNodeIndex,
    anchorOffset: startResolved.offset,
    focusNodeIndex,
    focusOffset: endResolved.offset
  };
}

function _findSelectionNodesByIndex($parent, anchorNodeIndex, focusNodeIndex) {
  let $anchor = undefined;
  let $focus  = undefined;
  let index = 0;

  function dfs(node) {
    if (!node) return;
    if ($anchor && $focus) return;

    // VALU-SYNC: Skip overlay elements (same reason as in findSelectionIndicesDFS)
    if (node.nodeType === Node.ELEMENT_NODE && node.dataset?.valuSyncIgnore) {
      return;
    }

    if (node.nodeType === Node.TEXT_NODE) {
      if (index === anchorNodeIndex) $anchor = node;
      if (index === focusNodeIndex)  $focus  = node;
      index++;
      return;
    }

    for (let c of node.childNodes) dfs(c);
  }

  dfs($parent);
  return { $anchor, $focus };
}

function restoreSelectionFromIndices($parent, indices) {
  const { anchorNodeIndex, anchorOffset, focusNodeIndex, focusOffset } = indices;

  const { $anchor, $focus } = _findSelectionNodesByIndex(
    $parent,
    anchorNodeIndex,
    focusNodeIndex
  );

  if (!$anchor || !$focus) return false;

  const sel = window.document.getSelection();
  sel.removeAllRanges();

  const range = window.document.createRange();
  range.setStart($anchor, Math.min(anchorOffset, $anchor.textContent.length));
  range.setEnd($focus,   Math.min(focusOffset, $focus.textContent.length));

  sel.addRange(range);
  return true;
}

export { findSelectionIndicesDFS, restoreSelectionFromIndices };

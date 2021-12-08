/* Copyright 2018 Mozilla Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const compatibilityParams = Object.create(null);
if (typeof PDFJSDev === "undefined" || PDFJSDev.test("GENERIC")) {
  const userAgent =
    (typeof navigator !== "undefined" && navigator.userAgent) || "";
  const platform =
    (typeof navigator !== "undefined" && navigator.platform) || "";
  const maxTouchPoints =
    (typeof navigator !== "undefined" && navigator.maxTouchPoints) || 1;

  const isAndroid = /Android/.test(userAgent);
  const isIOS =
    /\b(iPad|iPhone|iPod)(?=;)/.test(userAgent) ||
    (platform === "MacIntel" && maxTouchPoints > 1);
  const isIOSChrome = /CriOS/.test(userAgent);

  // Disables URL.createObjectURL() usage in some environments.
  // Support: Chrome on iOS
  (function checkOnBlobSupport() {
    // Sometimes Chrome on iOS loses data created with createObjectURL(),
    // see issue 8081.
    if (isIOSChrome) {
      compatibilityParams.disableCreateObjectURL = true;
    }
  })();

  // Limit canvas size to 5 mega-pixels on mobile.
  // Support: Android, iOS
  (function checkCanvasSizeLimitation() {
    if (isIOS || isAndroid) {
      compatibilityParams.maxCanvasPixels = 5242880;
    }
  })();
}

const OptionKind = {
  VIEWER: 0x02,
  API: 0x04,
  WORKER: 0x08,
  PREFERENCE: 0x80,
};

let SHA256 = function() {
  let root = typeof window === "object" ? window : {};
  let NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process == "object" && process.versions && process.versions.node;
  if (NODE_JS) {
    root = global;
  }
  let COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === "object" && module.exports;
  let AMD = typeof define === "function" && define.amd;
  let ARRAY_BUFFER = typeof ArrayBuffer !== "undefined";
  let HEX_CHARS = "0123456789abcdef".split("");
  let EXTRA = [-2147483648, 8388608, 32768, 128];
  let SHIFT = [24, 16, 8, 0];
  let K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let OUTPUT_TYPES = ["hex", "array", "digest", "arrayBuffer"];

  let blocks = [];

  let createOutputMethod = function(outputType, is224) {
    return function(message) {
      return new Sha256(is224, true).update(message)[outputType]();
    };
  };

  let createMethod = function(is224) {
    let method = createOutputMethod("hex", is224);
    if (NODE_JS) {
      method = nodeWrap(method, is224);
    }
    method.create = function() {
      return new Sha256(is224);
    };
    method.update = function(message) {
      return method.create().update(message);
    };
    for (let i = 0; i < OUTPUT_TYPES.length; ++i) {
      let type = OUTPUT_TYPES[i];
      method[type] = createOutputMethod(type, is224);
    }
    return method;
  };

  let nodeWrap = function(method, is224) {
    let crypto = require("crypto");
    let Buffer = require("buffer").Buffer;
    let algorithm = is224 ? "sha224" : "sha256";
    let nodeMethod = function(message) {
      if (typeof message === "string") {
        return crypto.createHash(algorithm).update(message, "utf8").digest("hex");
      } else if (ARRAY_BUFFER && message instanceof ArrayBuffer) {
        message = new Uint8Array(message);
      } else if (message.length === undefined) {
        return method(message);
      }
      return crypto.createHash(algorithm).update(new Buffer(message)).digest("hex");
    };
    return nodeMethod;
  };

  function Sha256(is224, sharedMemory) {
    if (sharedMemory) {
      blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
            blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      this.blocks = blocks;
    } else {
      this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }

    if (is224) {
      this.h0 = 0xc1059ed8;
      this.h1 = 0x367cd507;
      this.h2 = 0x3070dd17;
      this.h3 = 0xf70e5939;
      this.h4 = 0xffc00b31;
      this.h5 = 0x68581511;
      this.h6 = 0x64f98fa7;
      this.h7 = 0xbefa4fa4;
    } else { // 256
      this.h0 = 0x6a09e667;
      this.h1 = 0xbb67ae85;
      this.h2 = 0x3c6ef372;
      this.h3 = 0xa54ff53a;
      this.h4 = 0x510e527f;
      this.h5 = 0x9b05688c;
      this.h6 = 0x1f83d9ab;
      this.h7 = 0x5be0cd19;
    }

    this.block = this.start = this.bytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
    this.is224 = is224;
  }

  Sha256.prototype.update = function(message) {
    if (this.finalized) {
      return;
    }
    let notString = typeof (message) !== "string";
    if (notString && ARRAY_BUFFER && message instanceof root.ArrayBuffer) {
      message = new Uint8Array(message);
    }
    let code, index = 0, i, length = message.length || 0, blocks = this.blocks;

    while (index < length) {
      if (this.hashed) {
        this.hashed = false;
        blocks[0] = this.block;
        blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
            blocks[8] = blocks[9] = blocks[10] = blocks[11] =
              blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      }

      if (notString) {
        for (i = this.start; index < length && i < 64; ++index) {
          blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = this.start; index < length && i < 64; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else if (code < 0xd800 || code >= 0xe000) {
            blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
            blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          }
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;
      if (i >= 64) {
        this.block = blocks[16];
        this.start = i - 64;
        this.hash();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }
    return this;
  };

  Sha256.prototype.finalize = function() {
    if (this.finalized) {
      return;
    }
    this.finalized = true;
    let blocks = this.blocks, i = this.lastByteIndex;
    blocks[16] = this.block;
    blocks[i >> 2] |= EXTRA[i & 3];
    this.block = blocks[16];
    if (i >= 56) {
      if (!this.hashed) {
        this.hash();
      }
      blocks[0] = this.block;
      blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
            blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
    }
    blocks[15] = this.bytes << 3;
    this.hash();
  };

  Sha256.prototype.hash = function() {
    let a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6,
      h = this.h7, blocks = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;

    for (j = 16; j < 64; ++j) {
      // rightrotate
      t1 = blocks[j - 15];
      s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
      t1 = blocks[j - 2];
      s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
      blocks[j] = blocks[j - 16] + s0 + blocks[j - 7] + s1 << 0;
    }

    bc = b & c;
    for (j = 0; j < 64; j += 4) {
      if (this.first) {
        if (this.is224) {
          ab = 300032;
          t1 = blocks[0] - 1413257819;
          h = t1 - 150054599 << 0;
          d = t1 + 24177077 << 0;
        } else {
          ab = 704751109;
          t1 = blocks[0] - 210244248;
          h = t1 - 1521486534 << 0;
          d = t1 + 143694565 << 0;
        }
        this.first = false;
      } else {
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ab = a & b;
        maj = ab ^ (a & c) ^ bc;
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + K[j] + blocks[j];
        t2 = s0 + maj;
        h = d + t1 << 0;
        d = t1 + t2 << 0;
      }
      s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
      s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
      da = d & a;
      maj = da ^ (d & b) ^ ab;
      ch = (h & e) ^ (~h & f);
      t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
      t2 = s0 + maj;
      g = c + t1 << 0;
      c = t1 + t2 << 0;
      s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
      s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
      cd = c & d;
      maj = cd ^ (c & a) ^ da;
      ch = (g & h) ^ (~g & e);
      t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
      t2 = s0 + maj;
      f = b + t1 << 0;
      b = t1 + t2 << 0;
      s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
      s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
      bc = b & c;
      maj = bc ^ (b & d) ^ cd;
      ch = (f & g) ^ (~f & h);
      t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
      t2 = s0 + maj;
      e = a + t1 << 0;
      a = t1 + t2 << 0;
    }

    this.h0 = this.h0 + a << 0;
    this.h1 = this.h1 + b << 0;
    this.h2 = this.h2 + c << 0;
    this.h3 = this.h3 + d << 0;
    this.h4 = this.h4 + e << 0;
    this.h5 = this.h5 + f << 0;
    this.h6 = this.h6 + g << 0;
    this.h7 = this.h7 + h << 0;
  };

  Sha256.prototype.hex = function() {
    this.finalize();

    let h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    let hex = HEX_CHARS[(h0 >> 28) & 0x0F] + HEX_CHARS[(h0 >> 24) & 0x0F] +
      HEX_CHARS[(h0 >> 20) & 0x0F] + HEX_CHARS[(h0 >> 16) & 0x0F] +
      HEX_CHARS[(h0 >> 12) & 0x0F] + HEX_CHARS[(h0 >> 8) & 0x0F] +
      HEX_CHARS[(h0 >> 4) & 0x0F] + HEX_CHARS[h0 & 0x0F] +
      HEX_CHARS[(h1 >> 28) & 0x0F] + HEX_CHARS[(h1 >> 24) & 0x0F] +
      HEX_CHARS[(h1 >> 20) & 0x0F] + HEX_CHARS[(h1 >> 16) & 0x0F] +
      HEX_CHARS[(h1 >> 12) & 0x0F] + HEX_CHARS[(h1 >> 8) & 0x0F] +
      HEX_CHARS[(h1 >> 4) & 0x0F] + HEX_CHARS[h1 & 0x0F] +
      HEX_CHARS[(h2 >> 28) & 0x0F] + HEX_CHARS[(h2 >> 24) & 0x0F] +
      HEX_CHARS[(h2 >> 20) & 0x0F] + HEX_CHARS[(h2 >> 16) & 0x0F] +
      HEX_CHARS[(h2 >> 12) & 0x0F] + HEX_CHARS[(h2 >> 8) & 0x0F] +
      HEX_CHARS[(h2 >> 4) & 0x0F] + HEX_CHARS[h2 & 0x0F] +
      HEX_CHARS[(h3 >> 28) & 0x0F] + HEX_CHARS[(h3 >> 24) & 0x0F] +
      HEX_CHARS[(h3 >> 20) & 0x0F] + HEX_CHARS[(h3 >> 16) & 0x0F] +
      HEX_CHARS[(h3 >> 12) & 0x0F] + HEX_CHARS[(h3 >> 8) & 0x0F] +
      HEX_CHARS[(h3 >> 4) & 0x0F] + HEX_CHARS[h3 & 0x0F] +
      HEX_CHARS[(h4 >> 28) & 0x0F] + HEX_CHARS[(h4 >> 24) & 0x0F] +
      HEX_CHARS[(h4 >> 20) & 0x0F] + HEX_CHARS[(h4 >> 16) & 0x0F] +
      HEX_CHARS[(h4 >> 12) & 0x0F] + HEX_CHARS[(h4 >> 8) & 0x0F] +
      HEX_CHARS[(h4 >> 4) & 0x0F] + HEX_CHARS[h4 & 0x0F] +
      HEX_CHARS[(h5 >> 28) & 0x0F] + HEX_CHARS[(h5 >> 24) & 0x0F] +
      HEX_CHARS[(h5 >> 20) & 0x0F] + HEX_CHARS[(h5 >> 16) & 0x0F] +
      HEX_CHARS[(h5 >> 12) & 0x0F] + HEX_CHARS[(h5 >> 8) & 0x0F] +
      HEX_CHARS[(h5 >> 4) & 0x0F] + HEX_CHARS[h5 & 0x0F] +
      HEX_CHARS[(h6 >> 28) & 0x0F] + HEX_CHARS[(h6 >> 24) & 0x0F] +
      HEX_CHARS[(h6 >> 20) & 0x0F] + HEX_CHARS[(h6 >> 16) & 0x0F] +
      HEX_CHARS[(h6 >> 12) & 0x0F] + HEX_CHARS[(h6 >> 8) & 0x0F] +
      HEX_CHARS[(h6 >> 4) & 0x0F] + HEX_CHARS[h6 & 0x0F];
    if (!this.is224) {
      hex += HEX_CHARS[(h7 >> 28) & 0x0F] + HEX_CHARS[(h7 >> 24) & 0x0F] +
        HEX_CHARS[(h7 >> 20) & 0x0F] + HEX_CHARS[(h7 >> 16) & 0x0F] +
        HEX_CHARS[(h7 >> 12) & 0x0F] + HEX_CHARS[(h7 >> 8) & 0x0F] +
        HEX_CHARS[(h7 >> 4) & 0x0F] + HEX_CHARS[h7 & 0x0F];
    }
    return hex;
  };

  Sha256.prototype.toString = Sha256.prototype.hex;

  Sha256.prototype.digest = function() {
    this.finalize();

    let h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    let arr = [
      (h0 >> 24) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 8) & 0xFF, h0 & 0xFF,
      (h1 >> 24) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 8) & 0xFF, h1 & 0xFF,
      (h2 >> 24) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 8) & 0xFF, h2 & 0xFF,
      (h3 >> 24) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 8) & 0xFF, h3 & 0xFF,
      (h4 >> 24) & 0xFF, (h4 >> 16) & 0xFF, (h4 >> 8) & 0xFF, h4 & 0xFF,
      (h5 >> 24) & 0xFF, (h5 >> 16) & 0xFF, (h5 >> 8) & 0xFF, h5 & 0xFF,
      (h6 >> 24) & 0xFF, (h6 >> 16) & 0xFF, (h6 >> 8) & 0xFF, h6 & 0xFF,
    ];
    if (!this.is224) {
      arr.push((h7 >> 24) & 0xFF, (h7 >> 16) & 0xFF, (h7 >> 8) & 0xFF, h7 & 0xFF);
    }
    return arr;
  };

  Sha256.prototype.array = Sha256.prototype.digest;

  Sha256.prototype.arrayBuffer = function() {
    this.finalize();

    let buffer = new ArrayBuffer(this.is224 ? 28 : 32);
    let dataView = new DataView(buffer);
    dataView.setUint32(0, this.h0);
    dataView.setUint32(4, this.h1);
    dataView.setUint32(8, this.h2);
    dataView.setUint32(12, this.h3);
    dataView.setUint32(16, this.h4);
    dataView.setUint32(20, this.h5);
    dataView.setUint32(24, this.h6);
    if (!this.is224) {
      dataView.setUint32(28, this.h7);
    }
    return buffer;
  };

  return createMethod();
};

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
    let isSync = _urlParams.get("sync") || 0;
    let isPresent = _urlParams.get("present") || 0;
    let sessionId = _urlParams.get("session");

    url = "https://api.roomful.net/api/v0/resource/" + resourceId + "?sessionId=" + sessionId;

    let _findSelectionNodesByElements = function($parent, $anchor, $focus, fixNestedIndex = 0) {
      let anchorNodeIndex = -1, focusNodeIndex = -1;

      if ($parent.hasChildNodes()) {
        let children = [...$parent.childNodes];
        for (let i = 0; children.length > i; i++) {
          if (children[i].nodeType === root.document.ELEMENT_NODE) {
            if (children[i].hasChildNodes()) {
              let {
                anchorNodeIndex: nestedAnchorIndex,
                focusNodeIndex: nestedFocusNodeIndex,
                fixNestedIndex: nestedFixNestedIndex,
              } = _findSelectionNodesByElements(children[i], $anchor, $focus, i + fixNestedIndex);

              fixNestedIndex = nestedFixNestedIndex + 1;

              if (nestedAnchorIndex !== -1) {
                anchorNodeIndex = nestedAnchorIndex;
              }
              if (nestedFocusNodeIndex !== -1) {
                focusNodeIndex = nestedFocusNodeIndex;
              }

              if (anchorNodeIndex !== -1 && focusNodeIndex !== -1) {
                return {
                  anchorNodeIndex: anchorNodeIndex,
                  focusNodeIndex: focusNodeIndex,
                  fixNestedIndex: fixNestedIndex,
                };
              }
            }
          }

          if (children[i].nodeType === root.document.TEXT_NODE) {
            if (children[i] === $anchor) {
              anchorNodeIndex = fixNestedIndex + i;
            }
            if (children[i] === $focus) {
              focusNodeIndex = fixNestedIndex + i;
            }

            if (anchorNodeIndex !== -1 && focusNodeIndex !== -1) {
              return {
                anchorNodeIndex: anchorNodeIndex,
                focusNodeIndex: focusNodeIndex,
                fixNestedIndex: fixNestedIndex,
              };
            }
          }
        }
      }

      return {
        anchorNodeIndex: anchorNodeIndex,
        focusNodeIndex: focusNodeIndex,
        fixNestedIndex: fixNestedIndex,
      };
    };

    let _findSelectionNodesByIndex = function($parent, anchorNodeIndex, focusNodeIndex, fixNestedIndex = 0) {
      let $anchor = undefined;
      let $focus = undefined;

      if ($parent.hasChildNodes()) {
        let children = [...$parent.childNodes];
        for (let i = 0; children.length > i; i++) {
          if (children[i].nodeType === root.document.ELEMENT_NODE) {
            if (children[i].hasChildNodes()) {
              let {
                $anchor: $nestedAnchor,
                $focus: $nestedFocus,
                fixNestedIndex: nestedFixNestedIndex,
              } = _findSelectionNodesByIndex(children[i], anchorNodeIndex, focusNodeIndex, i + fixNestedIndex);

              fixNestedIndex = nestedFixNestedIndex + 1;

              if ($nestedAnchor !== undefined) {
                $anchor = $nestedAnchor;
              }
              if ($nestedFocus !== undefined) {
                $focus = $nestedFocus;
              }

              if ($anchor !== undefined && $focus !== undefined) {
                return {
                  $anchor: $anchor,
                  $focus: $focus,
                  fixNestedIndex: fixNestedIndex,
                };
              }
            }
          }

          if (children[i].nodeType === root.document.TEXT_NODE) {
            if (i + fixNestedIndex === anchorNodeIndex) {
              $anchor = children[i];
            }
            if (i + fixNestedIndex === focusNodeIndex) {
              $focus = children[i];
            }

            if ($anchor !== undefined && $focus !== undefined) {
              return {
                $anchor: $anchor,
                $focus: $focus,
                fixNestedIndex: fixNestedIndex,
              };
            }
          }
        }
      }

      return {
        $anchor: $anchor,
        $focus: $focus,
        fixNestedIndex: fixNestedIndex,
      };
    };

    let _highlightSelection = function($anchor, $focus, startRangeOffset, endRangeOffset, selectedText) {
      let rangeSelection = new Range();
      rangeSelection.setStart($anchor, startRangeOffset);
      rangeSelection.setEnd($focus, endRangeOffset);

      if (rangeSelection && $anchor.parentNode === $focus.parentNode) {
        let span = root.document.createElement("span");
        span.className = "highlight";
        span.innerHTML = selectedText;
        rangeSelection.deleteContents();
        rangeSelection.insertNode(span);
      }
    };

    let _highlight = function($anchor, $focus, startRangeOffset, endRangeOffset, length) {
      let highlighted = false;

      let $anchorParent = $anchor.parentNode;
      let $focusParent = $focus.parentNode;

      let rangeSelection = new Range();
      rangeSelection.setStart($anchor, startRangeOffset);
      rangeSelection.setEnd($focus, endRangeOffset);

      let selection = root.document.getSelection();
      selection.removeAllRanges();
      selection.addRange(rangeSelection);

      // let selectedText = rangeSelection.toString();

      // if (length === (endRangeOffset - startRangeOffset)) {
      // highlighted = true;
      // if ($anchorParent.className !== 'highlight') {
      // _highlightSelection($anchor, $focus, startRangeOffset, endRangeOffset, selectedText);
      // } else {
      // let afterText = selectedText + '<span class="highlight">' + anchorParent.innerHTML.substr(endRangeOffset) + '</span>';
      // $anchorParent.innerHTML = $anchorParent.innerHTML.substr(0, startRangeOffset);
      // $anchorParent.insertAdjacentHTML('afterend', afterText);
      // }
      // } else {
      // if ($anchorParent.className !== 'highlight' && $focusParent.className !== 'highlight') {
      // _highlightSelection($anchor, $focus, startRangeOffset, endRangeOffset, selectedText);
      // highlighted = true;
      // }
      // }

      // if (!highlighted) _highlightSelection($anchor, $focus, startRangeOffset, endRangeOffset, selectedText);

      // root.document.querySelectorAll('.highlight').forEach(function ($element) {
      // if ($element.innerHTML === '') $element.remove();
      // });
    };

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
          let { $anchor, $focus } = _findSelectionNodesByIndex($element, data.anchorNodeIndex, data.focusNodeIndex);
          if ($anchor === undefined || $focus === undefined) {
            return;
          }

          _highlight($anchor, $focus, data.startRangeOffset, data.endRangeOffset, data.length);
        }, $pdfViewer);
      }
    };

    root.document.addEventListener("DOMContentLoaded", function() {
      let startMouseXPosition = 0;

      let OnSelectionTextEvent = function(inverseMouseSelection = false, $element) {
        if ($element === undefined) {
          $element = root.document.querySelector(".pdfViewer .page");
        }
        let page = parseInt($element.getAttribute("data-page-number") || 0);

        let selection = root.document.getSelection();
        let length = selection.toString().length;

        if (Math.abs(length) === 0) {
          return;
        }

        let $anchor = selection.anchorNode;
        let $focus = selection.focusNode;

        if (inverseMouseSelection) {
          $anchor = selection.focusNode;
          $focus = selection.anchorNode;
        }

        let { anchorNodeIndex, focusNodeIndex } = _findSelectionNodesByElements($element, $anchor, $focus);
        if (anchorNodeIndex === -1 || focusNodeIndex === -1) {
          return;
        }

        let selectionRange = selection.getRangeAt(0);
        let startRangeOffset = selectionRange.startOffset;
        let endRangeOffset = selectionRange.endOffset;

        root.console.info("Roomful socket sync request selection text in pdf: ", page);
        socket.emit("videochat:sync:pdfTextSelected", {
          data: {
            videochatId: videoChatId,
            roomId: roomId,
            propId: propId,
            resourceId: resourceId,
            page: page,
            anchorNodeIndex: anchorNodeIndex,
            focusNodeIndex: focusNodeIndex,
            startRangeOffset: startRangeOffset,
            endRangeOffset: endRangeOffset,
            length: length,
          },
          "event": {
            id: SHA256()((new Date()).toISOString()),
            time: new Date / 1e3 | 0,
          },
        }, function(response) {
          if (response.data && !response.error.status) {
            // root.document.execCommand('copy');
            // _highlight($anchor, $focus, startRangeOffset, endRangeOffset, length);
            // selection.removeAllRanges();
            root.selectionTrigger = true;
          }
        });
      };

      let socket = root.io.connect("https://api.roomful.net", {
        path: "/socket",
        protocol: "wss:",
        allowRequest: true,
        transports: ["websocket"],
        upgrade: false,
        autoConnect: true,
        query: "isAdditional=true&sessionId=" + sessionId,
      });

      socket.on("connect", function() {
        if (isPresent === 1 || isSync === 1) {
          socket.emit("videochat:subscribe", {
            data: {
              videochatId: videoChatId,
            },
            "event": {
              id: SHA256()((new Date()).toISOString()),
              time: new Date / 1e3 | 0,
            },
          }, function(e) {
            console.log(e);
          });
        }

        root.console.info("Roomful socket is opened.");

        root.addEventListener("mousedown", function(e) {
          if (e.button === 0 && isPresent === 1) {
            let $element = e.target.closest(".pdfViewer .page");
            if ($element) {
              startMouseXPosition = e.pageX;
              if (root.selectionTrigger === true) {
                root.clearAllSelections(null, root.document.querySelector(".pdfViewer"));
              }
            }
          }
        });

        root.addEventListener("mouseup", function(e) {
          if (e.button === 0 && isPresent === 1) {
            let $element = e.target.closest(".pdfViewer .page");
            if ($element) {
              let mouseXPosition = e.pageX - startMouseXPosition;
              OnSelectionTextEvent(mouseXPosition < 0, $element);
            }
          }
        });
      });

      socket.on("videochat:sync:resourcePageChanged", function(response) {
        if (isPresent === 1 || isSync !== 1) {
          return;
        }

        if (response.data && !response.error.status) {
          let _videoChatId = response.data.videochatId;
          let _roomId = response.data.roomId;
          let _propId = response.data.propId;
          let _resourceId = response.data.resourceId;
          let _page = response.data.page;

          if (isSync === 1
            && _videoChatId === videoChatId
            && _roomId === roomId
            && _propId === propId
            && _resourceId === resourceId
            && _page !== PDFViewerApplication.page
          ) {
            root.console.info("Roomful socket synced you pdf page: ", _page);

            root.resourcePageStartNumber = _page;
            PDFViewerApplication.page = _page;
          }
        }
      });

      socket.on("videochat:sync:pdfTextSelected", function(response) {
        if (isPresent === 1 || isSync !== 1) {
          return;
        }
        if (response.data && !response.error.status) {
          let _videoChatId = response.data.videochatId;
          let _roomId = response.data.roomId;
          let _propId = response.data.propId;
          let _resourceId = response.data.resourceId;
          let _page = response.data.page;
          let _anchorNodeIndex = response.data.anchorNodeIndex;
          let _focusNodeIndex = response.data.focusNodeIndex;
          let _startRangeOffset = response.data.startRangeOffset;
          let _endRangeOffset = response.data.endRangeOffset;
          let _length = response.data.length;

          if (isSync === 1
            && _videoChatId === videoChatId
            && _roomId === roomId
            && _propId === propId
            && _resourceId === resourceId
          ) {
            root.console.info("Roomful socket synced you pdf selection: ", _page);

            root.resourcePageStartNumber = _page;
            root.resourcePageCurrentSelection = {
              page: _page,
              anchorNodeIndex: _anchorNodeIndex,
              focusNodeIndex: _focusNodeIndex,
              startRangeOffset: _startRangeOffset,
              endRangeOffset: _endRangeOffset,
              length: _length,
            };

            root.onHighlightReceive(root.resourcePageCurrentSelection);
          }
        }
      });

      root.resourcePageChanged = function(page) {
        if (isPresent !== 1) {
          return;
        }
        if (page === undefined || page < 0) {
          page = 0;
        }

        root.console.info("Roomful socket sync request pdf page: ", page);

        socket.emit("videochat:sync:resourcePageChanged", {
          data: {
            videochatId: videoChatId,
            roomId: roomId,
            propId: propId,
            resourceId: resourceId,
            page: page,
          },
          "event": {
            id: SHA256()((new Date()).toISOString()),
            time: new Date / 1e3 | 0,
          },
        }, function(e) {
          console.log(e);
        });
      };

      root.analyticPdfDownload = function() {
        if (socket && socket.connected) {
          socket.emit("analytics:userDownloadedPDF", {
            data: {
              resourceId: resourceId,
            },
            "event": {
              id: SHA256()((new Date()).toISOString()),
              time: new Date / 1e3 | 0,
            },
          }, function(e) {
            console.log(e);
          });
        }
      };

      root.analyticPdfPrint = function() {
        if (socket && socket.connected) {
          socket.emit("analytics:userPrintedPDF", {
            data: {
              resourceId: resourceId,
            },
            "event": {
              id: SHA256()((new Date()).toISOString()),
              time: new Date / 1e3 | 0,
            },
          }, function(e) {
            console.log(e);
          });
        }
      };
    });
  } catch (e) {
    console.warn(e);
  }
}

/**
 * NOTE: These options are used to generate the `default_preferences.json` file,
 *       see `OptionKind.PREFERENCE`, hence the values below must use only
 *       primitive types and cannot rely on any imported types.
 */
const defaultOptions = {
  annotationMode: {
    /** @type {number} */
    value: 2,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  cursorToolOnLoad: {
    /** @type {number} */
    value: 0,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  defaultUrl: {
    /** @type {string} */
    value: url,
    kind: OptionKind.VIEWER,
  },
  defaultZoomValue: {
    /** @type {string} */
    value: "",
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  disableHistory: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.VIEWER,
  },
  disablePageLabels: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  enablePermissions: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  enablePrintAutoRotate: {
    /** @type {boolean} */
    value: true,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  enableScripting: {
    /** @type {boolean} */
    value: typeof PDFJSDev === "undefined" || !PDFJSDev.test("CHROME"),
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  externalLinkRel: {
    /** @type {string} */
    value: "noopener noreferrer nofollow",
    kind: OptionKind.VIEWER,
  },
  externalLinkTarget: {
    /** @type {number} */
    value: 0,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  historyUpdateUrl: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  ignoreDestinationZoom: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  imageResourcesPath: {
    /** @type {string} */
    value: "./images/",
    kind: OptionKind.VIEWER,
  },
  maxCanvasPixels: {
    /** @type {number} */
    value: 16777216,
    compatibility: compatibilityParams.maxCanvasPixels,
    kind: OptionKind.VIEWER,
  },
  pdfBugEnabled: {
    /** @type {boolean} */
    value: typeof PDFJSDev === "undefined" || !PDFJSDev.test("PRODUCTION"),
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  printResolution: {
    /** @type {number} */
    value: 150,
    kind: OptionKind.VIEWER,
  },
  renderer: {
    /** @type {string} */
    value: "canvas",
    kind: OptionKind.VIEWER,
  },
  sidebarViewOnLoad: {
    /** @type {number} */
    value: -1,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  scrollModeOnLoad: {
    /** @type {number} */
    value: -1,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  spreadModeOnLoad: {
    /** @type {number} */
    value: -1,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  textLayerMode: {
    /** @type {number} */
    value: 1,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  useOnlyCssZoom: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  viewerCssTheme: {
    /** @type {number} */
    value: typeof PDFJSDev !== "undefined" && PDFJSDev.test("CHROME") ? 2 : 0,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },
  viewOnLoad: {
    /** @type {boolean} */
    value: 0,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  },

  cMapPacked: {
    /** @type {boolean} */
    value: true,
    kind: OptionKind.API,
  },
  cMapUrl: {
    /** @type {string} */
    value:
      typeof PDFJSDev === "undefined" || !PDFJSDev.test("PRODUCTION")
        ? "../external/bcmaps/"
        : "../web/cmaps/",
    kind: OptionKind.API,
  },
  disableAutoFetch: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.API + OptionKind.PREFERENCE,
  },
  disableFontFace: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.API + OptionKind.PREFERENCE,
  },
  disableRange: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.API + OptionKind.PREFERENCE,
  },
  disableStream: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.API + OptionKind.PREFERENCE,
  },
  docBaseUrl: {
    /** @type {string} */
    value: "",
    kind: OptionKind.API,
  },
  enableXfa: {
    /** @type {boolean} */
    value: true,
    kind: OptionKind.API + OptionKind.PREFERENCE,
  },
  fontExtraProperties: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.API,
  },
  isEvalSupported: {
    /** @type {boolean} */
    value: true,
    kind: OptionKind.API,
  },
  maxImageSize: {
    /** @type {number} */
    value: -1,
    kind: OptionKind.API,
  },
  pdfBug: {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.API,
  },
  standardFontDataUrl: {
    /** @type {string} */
    value:
      typeof PDFJSDev === "undefined" || !PDFJSDev.test("PRODUCTION")
        ? "../external/standard_fonts/"
        : "../web/standard_fonts/",
    kind: OptionKind.API,
  },
  verbosity: {
    /** @type {number} */
    value: 1,
    kind: OptionKind.API,
  },

  workerPort: {
    /** @type {Object} */
    value: null,
    kind: OptionKind.WORKER,
  },
  workerSrc: {
    /** @type {string} */
    value:
      typeof PDFJSDev === "undefined" || !PDFJSDev.test("PRODUCTION")
        ? "../src/worker_loader.js"
        : "../build/pdf.worker.js",
    kind: OptionKind.WORKER,
  },
};
if (
  typeof PDFJSDev === "undefined" ||
  PDFJSDev.test("!PRODUCTION || GENERIC")
) {
  defaultOptions.disablePreferences = {
    /** @type {boolean} */
    value: typeof PDFJSDev !== "undefined" && PDFJSDev.test("TESTING"),
    kind: OptionKind.VIEWER,
  };
  defaultOptions.locale = {
    /** @type {string} */
    value: typeof navigator !== "undefined" ? navigator.language : "en-US",
    kind: OptionKind.VIEWER,
  };
  defaultOptions.sandboxBundleSrc = {
    /** @type {string} */
    value:
      typeof PDFJSDev === "undefined" || !PDFJSDev.test("PRODUCTION")
        ? "../build/dev-sandbox/pdf.sandbox.js"
        : "../build/pdf.sandbox.js",
    kind: OptionKind.VIEWER,
  };

  defaultOptions.renderer.kind += OptionKind.PREFERENCE;
} else if (PDFJSDev.test("CHROME")) {
  defaultOptions.disableTelemetry = {
    /** @type {boolean} */
    value: false,
    kind: OptionKind.VIEWER + OptionKind.PREFERENCE,
  };
  defaultOptions.sandboxBundleSrc = {
    /** @type {string} */
    value: "../build/pdf.sandbox.js",
    kind: OptionKind.VIEWER,
  };
}

const userOptions = Object.create(null);

class AppOptions {
  constructor() {
    throw new Error("Cannot initialize AppOptions.");
  }

  static get(name) {
    const userOption = userOptions[name];
    if (userOption !== undefined) {
      return userOption;
    }
    const defaultOption = defaultOptions[name];
    if (defaultOption !== undefined) {
      return defaultOption.compatibility ?? defaultOption.value;
    }
    return undefined;
  }

  static getAll(kind = null) {
    const options = Object.create(null);
    for (const name in defaultOptions) {
      const defaultOption = defaultOptions[name];
      if (kind) {
        if ((kind & defaultOption.kind) === 0) {
          continue;
        }
        if (kind === OptionKind.PREFERENCE) {
          const value = defaultOption.value,
            valueType = typeof value;

          if (
            valueType === "boolean" ||
            valueType === "string" ||
            (valueType === "number" && Number.isInteger(value))
          ) {
            options[name] = value;
            continue;
          }
          throw new Error(`Invalid type for preference: ${name}`);
        }
      }
      const userOption = userOptions[name];
      options[name] =
        userOption !== undefined
          ? userOption
          : defaultOption.compatibility ?? defaultOption.value;
    }
    return options;
  }

  static set(name, value) {
    userOptions[name] = value;
  }

  static setAll(options) {
    for (const name in options) {
      userOptions[name] = options[name];
    }
  }

  static remove(name) {
    delete userOptions[name];
  }

  /**
   * @ignore
   */
  static _hasUserOptions() {
    return Object.keys(userOptions).length > 0;
  }
}

export { AppOptions, compatibilityParams, OptionKind };

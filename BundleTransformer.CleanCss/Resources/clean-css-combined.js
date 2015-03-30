/*!
 * Clean-css v3.1.8
 * https://github.com/jakubpawlowicz/clean-css
 *
 * Copyright (C) 2014 JakubPawlowicz.com
 * Released under the terms of MIT license
 */
var CleanCss = (function(){
	var modules = {},
		loadedModules = {},
		require = function(name) {
			var result;
		
			if (typeof loadedModules[name] !== 'undefined') {
				result = loadedModules[name];
			}
			else {
				if (typeof modules[name] !== 'undefined') {
					result = modules[name].call(this);
					
					loadedModules[name] = (typeof result !== 'undefined') ? result : null;
					modules[name] = undefined;
				}
				else {
					throw new Error("Can't load '" + name + "' module.");
				}
			}
		
			return result;
		}
		;
		
	//#region URL: util
	modules['util'] = function () {
		var exports = {};
		
		function isObject(arg) {
			return typeof arg === 'object' && arg !== null;
		}
		exports.isObject = isObject;
		
		function objectToString(o) {
			return Object.prototype.toString.call(o);
		}
		
		function isRegExp(re) {
			return isObject(re) && objectToString(re) === '[object RegExp]';
		}
		exports.isRegExp = isRegExp;
		
		return exports;
	};
	//#endregion
	
	//#region URL: os
	modules['os'] = function () {
		var exports = {},
			isWindows = true;
			;
			
		exports.EOL = isWindows ? '\r\n' : '\n';
		
		return exports;
	};
	//#endregion
		
	//#region URL: /utils/chunker
	modules['/utils/chunker'] = function () {
		// Divides `data` into chunks of `chunkSize` for faster processing
		function Chunker(data, breakString, chunkSize) {
		  this.chunks = [];

		  for (var cursor = 0, dataSize = data.length; cursor < dataSize;) {
			var nextCursor = cursor + chunkSize > dataSize ?
			  dataSize - 1 :
			  cursor + chunkSize;

			if (data[nextCursor] != breakString)
			  nextCursor = data.indexOf(breakString, nextCursor);
			if (nextCursor == -1)
			  nextCursor = data.length - 1;

			this.chunks.push(data.substring(cursor, nextCursor + breakString.length));
			cursor = nextCursor + breakString.length;
		  }
		}

		Chunker.prototype.isEmpty = function () {
		  return this.chunks.length === 0;
		};

		Chunker.prototype.next = function () {
		  return this.chunks.shift();
		};
		
		return Chunker;
	};
	//#endregion
	
	//#region URL: /utils/splitter
	modules['/utils/splitter'] = function () {
		function Splitter(separator) {
		  this.separator = separator;
		}

		Splitter.prototype.split = function (value) {
		  if (value.indexOf(this.separator) === -1)
			return [value];

		  if (value.indexOf('(') === -1)
			return value.split(this.separator);

		  var level = 0;
		  var cursor = 0;
		  var lastStart = 0;
		  var len = value.length;
		  var tokens = [];

		  while (cursor++ < len) {
			if (value[cursor] == '(') {
			  level++;
			} else if (value[cursor] == ')') {
			  level--;
			} else if (value[cursor] == this.separator && level === 0) {
			  tokens.push(value.substring(lastStart, cursor));
			  lastStart = cursor + 1;
			}
		  }

		  if (lastStart < cursor + 1)
			tokens.push(value.substring(lastStart));

		  return tokens;
		};
	
		return Splitter;
	};
	//#endregion
	
	//#region URL: /utils/extractors
	modules['/utils/extractors'] = function () {
		var Splitter = require('/utils/splitter');
//		var SourceMaps = require('/utils/source-maps');

		var Extractors = {
		  properties: function (string, context) {
			var tokenized = [];
			var list = [];
			var buffer = [];
			var all = [];
			var property;
			var isPropertyEnd;
			var isWhitespace;
			var wasWhitespace;
			var isSpecial;
			var wasSpecial;
			var current;
			var last;
			var secondToLast;
			var wasCloseParenthesis;
			var isEscape;
			var token;
//			var addSourceMap = context.addSourceMap;

			if (string.replace && string.indexOf(')') > 0)
			  string = string.replace(/\)([^\s_;:,\)])/g, /*context.addSourceMap ? ') __ESCAPED_COMMENT_CLEAN_CSS(0,-1)__$1' : */') $1');

			for (var i = 0, l = string.length; i < l; i++) {
			  current = string[i];
			  isPropertyEnd = current === ';';

			  isEscape = !isPropertyEnd && current == '_' && string.indexOf('__ESCAPED_COMMENT', i) === i;
			  if (isEscape) {
				if (buffer.length > 0) {
				  i--;
				  isPropertyEnd = true;
				} else {
				  var endOfEscape = string.indexOf('__', i + 1) + 2;
				  var comment = string.substring(i, endOfEscape);
				  i = endOfEscape - 1;

				  if (comment.indexOf('__ESCAPED_COMMENT_SPECIAL') === -1) {
//					if (addSourceMap)
//					  SourceMaps.track(comment, context, true);
					continue;
				  }
				  else {
					buffer = all = [comment];
				  }
				}
			  }

			  if (isPropertyEnd || isEscape) {
				if (wasWhitespace && buffer[buffer.length - 1] === ' ')
				  buffer.pop();
				if (buffer.length > 0) {
				  property = buffer.join('');
				  if (property.indexOf('{') === -1) {
					token = { value: property };
					tokenized.push(token);
					list.push(property);

//					if (addSourceMap)
//					  token.metadata = SourceMaps.saveAndTrack(all.join(''), context, !isEscape);
				  }
				}
				buffer = [];
				all = [];
			  } else {
				isWhitespace = current === ' ' || current === '\t' || current === '\n';
				isSpecial = current === ':' || current === '[' || current === ']' || current === ',' || current === '(' || current === ')';

				if (wasWhitespace && isSpecial) {
				  last = buffer[buffer.length - 1];
				  secondToLast = buffer[buffer.length - 2];
				  if (secondToLast != '+' && secondToLast != '-' && secondToLast != '/' && secondToLast != '*' && last != '(')
					buffer.pop();
				  buffer.push(current);
				} else if (isWhitespace && wasSpecial && !wasCloseParenthesis) {
				} else if (isWhitespace && !wasWhitespace && buffer.length > 0) {
				  buffer.push(' ');
				} else if (isWhitespace && buffer.length === 0) {
				} else if (isWhitespace && wasWhitespace) {
				} else {
				  buffer.push(isWhitespace ? ' ' : current);
				}

				all.push(current);
			  }

			  wasSpecial = isSpecial;
			  wasWhitespace = isWhitespace;
			  wasCloseParenthesis = current === ')';
			}

			if (wasWhitespace && buffer[buffer.length - 1] === ' ')
			  buffer.pop();
			if (buffer.length > 0) {
			  property = buffer.join('');
			  if (property.indexOf('{') === -1) {
				token = { value: property };
				tokenized.push(token);
				list.push(property);

//				if (addSourceMap)
//				  token.metadata = SourceMaps.saveAndTrack(all.join(''), context, false);
			  }
			} else if (all.indexOf('\n') > -1) {
//			  SourceMaps.track(all.join(''), context);
			}

			return {
			  list: list,
			  tokenized: tokenized
			};
		  },

		  selectors: function (string, context) {
			var tokenized = [];
			var list = [];
			var selectors = new Splitter(',').split(string);
//			var addSourceMap = context.addSourceMap;

			for (var i = 0, l = selectors.length; i < l; i++) {
			  var selector = selectors[i];

			  list.push(selector);

			  var token = { value: selector };
			  tokenized.push(token);

//			  if (addSourceMap)
//				token.metadata = SourceMaps.saveAndTrack(selector, context, true);
			}

			return {
			  list: list,
			  tokenized: tokenized
			};
		  }
		};
		
		return Extractors;
	};
	//#endregion
		
	//#region URL: /selectors/tokenizer
	modules['/selectors/tokenizer'] = function () {
		var Chunker = require('/utils/chunker');
		var Extract = require('/utils/extractors');
//		var SourceMaps = require('/utils/source-maps');

		var flatBlock = /(^@(font\-face|page|\-ms\-viewport|\-o\-viewport|viewport|counter\-style)|\\@.+?)/;

		function Tokenizer(minifyContext, addMetadata/*, addSourceMap*/) {
		  this.minifyContext = minifyContext;
		  this.addMetadata = addMetadata;
//		  this.addSourceMap = addSourceMap;
		}

		Tokenizer.prototype.toTokens = function (data) {
		  data = data.replace(/\r\n/g, '\n');

		  var chunker = new Chunker(data, '}', 128);
		  if (chunker.isEmpty())
			return [];

		  var context = {
			cursor: 0,
			mode: 'top',
			chunker: chunker,
			chunk: chunker.next(),
			outer: this.minifyContext,
			addMetadata: this.addMetadata,
//			addSourceMap: this.addSourceMap,
			state: [],
			line: 1,
			column: 0,
			source: undefined
		  };

		  return tokenize(context);
		};

		function whatsNext(context) {
		  var mode = context.mode;
		  var chunk = context.chunk;
		  var closest;

		  if (chunk.length == context.cursor) {
			if (context.chunker.isEmpty())
			  return null;

			context.chunk = chunk = context.chunker.next();
			context.cursor = 0;
		  }

		  if (mode == 'body') {
			closest = chunk.indexOf('}', context.cursor);
			return closest > -1 ?
			  [closest, 'bodyEnd'] :
			  null;
		  }

		  var nextSpecial = chunk.indexOf('@', context.cursor);
		  var nextEscape = chunk.indexOf('__ESCAPED_', context.cursor);
		  var nextBodyStart = chunk.indexOf('{', context.cursor);
		  var nextBodyEnd = chunk.indexOf('}', context.cursor);

		  if (nextEscape > -1 && /\S/.test(chunk.substring(context.cursor, nextEscape)))
			nextEscape = -1;

		  closest = nextSpecial;
		  if (closest == -1 || (nextEscape > -1 && nextEscape < closest))
			closest = nextEscape;
		  if (closest == -1 || (nextBodyStart > -1 && nextBodyStart < closest))
			closest = nextBodyStart;
		  if (closest == -1 || (nextBodyEnd > -1 && nextBodyEnd < closest))
			closest = nextBodyEnd;

		  if (closest == -1)
			return;
		  if (nextEscape === closest)
			return [closest, 'escape'];
		  if (nextBodyStart === closest)
			return [closest, 'bodyStart'];
		  if (nextBodyEnd === closest)
			return [closest, 'bodyEnd'];
		  if (nextSpecial === closest)
			return [closest, 'special'];
		}

		function tokenize(context) {
		  var chunk = context.chunk;
		  var tokenized = [];
		  var newToken;
		  var value;
//		  var addSourceMap = context.addSourceMap;

		  while (true) {
			var next = whatsNext(context);
			if (!next) {
			  var whatsLeft = context.chunk.substring(context.cursor);
			  if (whatsLeft.trim().length > 0) {
				if (context.mode == 'body') {
				  context.outer.warnings.push('Missing \'}\' after \'' + whatsLeft + '\'. Ignoring.');
				} else {
				  tokenized.push({ kind: 'text', value: whatsLeft });
				}
				context.cursor += whatsLeft.length;
			  }
			  break;
			}

			var nextSpecial = next[0];
			var what = next[1];
			var nextEnd;
			var oldMode;

			chunk = context.chunk;

			if (context.cursor != nextSpecial && what != 'bodyEnd') {
			  var spacing = chunk.substring(context.cursor, nextSpecial);
			  var leadingWhitespace = /^\s+/.exec(spacing);

			  if (leadingWhitespace) {
				context.cursor += leadingWhitespace[0].length;

//				if (addSourceMap)
//				  SourceMaps.track(leadingWhitespace[0], context);
			  }
			}

			if (what == 'special') {
			  var firstOpenBraceAt = chunk.indexOf('{', nextSpecial);
			  var firstSemicolonAt = chunk.indexOf(';', nextSpecial);
			  var isSingle = firstSemicolonAt > -1 && (firstOpenBraceAt == -1 || firstSemicolonAt < firstOpenBraceAt);
			  var isBroken = firstOpenBraceAt == -1 && firstSemicolonAt == -1;
			  if (isBroken) {
				context.outer.warnings.push('Broken declaration: \'' + chunk.substring(context.cursor) +  '\'.');
				context.cursor = chunk.length;
			  } else if (isSingle) {
				nextEnd = chunk.indexOf(';', nextSpecial + 1);

				value = chunk.substring(context.cursor, nextEnd + 1);
				newToken = { kind: 'at-rule', value: value };
				tokenized.push(newToken);

//				if (addSourceMap)
//				  newToken.metadata = SourceMaps.saveAndTrack(value, context, true);

				context.cursor = nextEnd + 1;
			  } else {
				nextEnd = chunk.indexOf('{', nextSpecial + 1);
				value = chunk.substring(context.cursor, nextEnd);

				var trimmedValue = value.trim();
				var isFlat = flatBlock.test(trimmedValue);
				oldMode = context.mode;
				context.cursor = nextEnd + 1;
				context.mode = isFlat ? 'body' : 'block';

				newToken = { kind: 'block', value: trimmedValue, isFlatBlock: isFlat };

//				if (addSourceMap)
//				  newToken.metadata = SourceMaps.saveAndTrack(value, context, true);

				newToken.body = tokenize(context);
				if (typeof newToken.body == 'string')
				  newToken.body = Extract.properties(newToken.body, context).tokenized;

				context.mode = oldMode;

//				if (addSourceMap)
//				  SourceMaps.suffix(context);

				tokenized.push(newToken);
			  }
			} else if (what == 'escape') {
			  nextEnd = chunk.indexOf('__', nextSpecial + 1);
			  var escaped = chunk.substring(context.cursor, nextEnd + 2);
			  var isStartSourceMarker = !!context.outer.sourceTracker.nextStart(escaped);
			  var isEndSourceMarker = !!context.outer.sourceTracker.nextEnd(escaped);

			  if (isStartSourceMarker) {
//				if (addSourceMap)
//				  SourceMaps.track(escaped, context);

				context.state.push({
				  source: context.source,
				  line: context.line,
				  column: context.column
				});
				context.source = context.outer.sourceTracker.nextStart(escaped).filename;
				context.line = 1;
				context.column = 0;
			  } else if (isEndSourceMarker) {
				var oldState = context.state.pop();
				context.source = oldState.source;
				context.line = oldState.line;
				context.column = oldState.column;

//				if (addSourceMap)
//				  SourceMaps.track(escaped, context);
			  } else {
				if (escaped.indexOf('__ESCAPED_COMMENT_SPECIAL') === 0)
				  tokenized.push({ kind: 'text', value: escaped });

//				if (addSourceMap)
//				  SourceMaps.track(escaped, context);
			  }

			  context.cursor = nextEnd + 2;
			} else if (what == 'bodyStart') {
			  var selectorData = Extract.selectors(chunk.substring(context.cursor, nextSpecial), context);

			  oldMode = context.mode;
			  context.cursor = nextSpecial + 1;
			  context.mode = 'body';

			  var bodyData = Extract.properties(tokenize(context), context);

//			  if (addSourceMap)
//				SourceMaps.suffix(context);

			  context.mode = oldMode;

			  newToken = {
				kind: 'selector',
				value: selectorData.tokenized,
				body: bodyData.tokenized
			  };
			  if (context.addMetadata) {
				newToken.metadata = {
				  body: bodyData.list.join(','),
				  bodiesList: bodyData.list,
				  selector: selectorData.list.join(','),
				  selectorsList: selectorData.list
				};
			  }
			  tokenized.push(newToken);
			} else if (what == 'bodyEnd') {
			  // extra closing brace at the top level can be safely ignored
			  if (context.mode == 'top') {
				var at = context.cursor;
				var warning = chunk[context.cursor] == '}' ?
				  'Unexpected \'}\' in \'' + chunk.substring(at - 20, at + 20) + '\'. Ignoring.' :
				  'Unexpected content: \'' + chunk.substring(at, nextSpecial + 1) + '\'. Ignoring.';

				context.outer.warnings.push(warning);
				context.cursor = nextSpecial + 1;
				continue;
			  }

//			  if (context.mode == 'block' && context.addSourceMap)
//				SourceMaps.track(chunk.substring(context.cursor, nextSpecial), context);
			  if (context.mode != 'block')
				tokenized = chunk.substring(context.cursor, nextSpecial);

			  context.cursor = nextSpecial + 1;

			  break;
			}
		  }

		  return tokenized;
		}
		
		return Tokenizer;
	};
	//#endregion
	
	//#region URL: /selectors/optimizers/clean-up
	modules['/selectors/optimizers/clean-up'] = function () {
		function removeWhitespace(match, value) {
		  return '[' + value.replace(/ /g, '') + ']';
		}

		function selectorSorter(s1, s2) {
		  return s1.value > s2.value ? 1 : -1;
		}

		var CleanUp = {
		  selectors: function (selectors, removeUnsupported, adjacentSpace) {
			var plain = [];
			var tokenized = [];

			for (var i = 0, l = selectors.length; i < l; i++) {
			  var selector = selectors[i];
			  var reduced = selector.value
				.replace(/\s+/g, ' ')
				.replace(/ ?, ?/g, ',')
				.replace(/\s*([>\+\~])\s*/g, '$1')
				.trim();

			  if (adjacentSpace && reduced.indexOf('nav') > 0)
				reduced = reduced.replace(/\+nav(\S|$)/, '+ nav$1');

			  if (removeUnsupported && (reduced.indexOf('*+html ') != -1 || reduced.indexOf('*:first-child+html ') != -1))
				continue;

			  if (reduced.indexOf('*') > -1) {
				reduced = reduced
				  .replace(/\*([:#\.\[])/g, '$1')
				  .replace(/^(\:first\-child)?\+html/, '*$1+html');
			  }

			  if (reduced.indexOf('[') > -1)
				reduced = reduced.replace(/\[([^\]]+)\]/g, removeWhitespace);

			  if (plain.indexOf(reduced) == -1) {
				plain.push(reduced);
				selector.value = reduced;
				tokenized.push(selector);
			  }
			}

			return {
			  list: plain.sort(),
			  tokenized: tokenized.sort(selectorSorter)
			};
		  },

		  selectorDuplicates: function (selectors) {
			var plain = [];
			var tokenized = [];

			for (var i = 0, l = selectors.length; i < l; i++) {
			  var selector = selectors[i];

			  if (plain.indexOf(selector.value) == -1) {
				plain.push(selector.value);
				tokenized.push(selector);
			  }
			}

			return {
			  list: plain.sort(),
			  tokenized: tokenized.sort(selectorSorter)
			};
		  },

		  block: function (block) {
			return block
			  .replace(/\s+/g, ' ')
			  .replace(/(,|:|\() /g, '$1')
			  .replace(/ ?\) ?/g, ')');
		  },

		  atRule: function (block) {
			return block
			  .replace(/\s+/g, ' ')
			  .trim();
		  }
		};
		
		return CleanUp;
	};
	//#endregion
	
	//#region URL: /colors/rgb
	modules['/colors/rgb'] = function () {
		function RGB(red, green, blue) {
		  this.red = red;
		  this.green = green;
		  this.blue = blue;
		}

		RGB.prototype.toHex = function () {
		  var red = Math.max(0, Math.min(~~this.red, 255));
		  var green = Math.max(0, Math.min(~~this.green, 255));
		  var blue = Math.max(0, Math.min(~~this.blue, 255));

		  // Credit: Asen  http://jsbin.com/UPUmaGOc/2/edit?js,console
		  return '#' + ('00000' + (red << 16 | green << 8 | blue).toString(16)).slice(-6);
		};
		
		return RGB;
	};
	//#endregion
	
	//#region URL: /colors/hsl
	modules['/colors/hsl'] = function () {
		// HSL to RGB converter. Both methods adapted from:
		// http://mjijackson.com/2008/02/rgb-to-hsl-and-rgb-to-hsv-color-model-conversion-algorithms-in-javascript

		function HSLColor(hue, saturation, lightness) {
		  this.hue = hue;
		  this.saturation = saturation;
		  this.lightness = lightness;
		}

		function hslToRgb(h, s, l) {
		  var r, g, b;

		  // normalize hue orientation b/w 0 and 360 degrees
		  h = h % 360;
		  if (h < 0)
			h += 360;
		  h = ~~h / 360;

		  if (s < 0)
			s = 0;
		  else if (s > 100)
			s = 100;
		  s = ~~s / 100;

		  if (l < 0)
			l = 0;
		  else if (l > 100)
			l = 100;
		  l = ~~l / 100;

		  if (s === 0) {
			r = g = b = l; // achromatic
		  } else {
			var q = l < 0.5 ?
			  l * (1 + s) :
			  l + s - l * s;
			var p = 2 * l - q;
			r = hueToRgb(p, q, h + 1/3);
			g = hueToRgb(p, q, h);
			b = hueToRgb(p, q, h - 1/3);
		  }

		  return [~~(r * 255), ~~(g * 255), ~~(b * 255)];
		}

		function hueToRgb(p, q, t) {
		  if (t < 0) t += 1;
		  if (t > 1) t -= 1;
		  if (t < 1/6) return p + (q - p) * 6 * t;
		  if (t < 1/2) return q;
		  if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
		  return p;
		}

		HSLColor.prototype.toHex = function () {
		  var asRgb = hslToRgb(this.hue, this.saturation, this.lightness);
		  var redAsHex = asRgb[0].toString(16);
		  var greenAsHex = asRgb[1].toString(16);
		  var blueAsHex = asRgb[2].toString(16);

		  return '#' +
			((redAsHex.length == 1 ? '0' : '') + redAsHex) +
			((greenAsHex.length == 1 ? '0' : '') + greenAsHex) +
			((blueAsHex.length == 1 ? '0' : '') + blueAsHex);
		};
		
		return HSLColor;
	};
	//#endregion
	
	//#region URL: /colors/hex-name-shortener
	modules['/colors/hex-name-shortener'] = function () {
		var HexNameShortener = {};

		var COLORS = {
		  aliceblue: '#f0f8ff',
		  antiquewhite: '#faebd7',
		  aqua: '#0ff',
		  aquamarine: '#7fffd4',
		  azure: '#f0ffff',
		  beige: '#f5f5dc',
		  bisque: '#ffe4c4',
		  black: '#000',
		  blanchedalmond: '#ffebcd',
		  blue: '#00f',
		  blueviolet: '#8a2be2',
		  brown: '#a52a2a',
		  burlywood: '#deb887',
		  cadetblue: '#5f9ea0',
		  chartreuse: '#7fff00',
		  chocolate: '#d2691e',
		  coral: '#ff7f50',
		  cornflowerblue: '#6495ed',
		  cornsilk: '#fff8dc',
		  crimson: '#dc143c',
		  cyan: '#0ff',
		  darkblue: '#00008b',
		  darkcyan: '#008b8b',
		  darkgoldenrod: '#b8860b',
		  darkgray: '#a9a9a9',
		  darkgreen: '#006400',
		  darkgrey: '#a9a9a9',
		  darkkhaki: '#bdb76b',
		  darkmagenta: '#8b008b',
		  darkolivegreen: '#556b2f',
		  darkorange: '#ff8c00',
		  darkorchid: '#9932cc',
		  darkred: '#8b0000',
		  darksalmon: '#e9967a',
		  darkseagreen: '#8fbc8f',
		  darkslateblue: '#483d8b',
		  darkslategray: '#2f4f4f',
		  darkslategrey: '#2f4f4f',
		  darkturquoise: '#00ced1',
		  darkviolet: '#9400d3',
		  deeppink: '#ff1493',
		  deepskyblue: '#00bfff',
		  dimgray: '#696969',
		  dimgrey: '#696969',
		  dodgerblue: '#1e90ff',
		  firebrick: '#b22222',
		  floralwhite: '#fffaf0',
		  forestgreen: '#228b22',
		  fuchsia: '#f0f',
		  gainsboro: '#dcdcdc',
		  ghostwhite: '#f8f8ff',
		  gold: '#ffd700',
		  goldenrod: '#daa520',
		  gray: '#808080',
		  green: '#008000',
		  greenyellow: '#adff2f',
		  grey: '#808080',
		  honeydew: '#f0fff0',
		  hotpink: '#ff69b4',
		  indianred: '#cd5c5c',
		  indigo: '#4b0082',
		  ivory: '#fffff0',
		  khaki: '#f0e68c',
		  lavender: '#e6e6fa',
		  lavenderblush: '#fff0f5',
		  lawngreen: '#7cfc00',
		  lemonchiffon: '#fffacd',
		  lightblue: '#add8e6',
		  lightcoral: '#f08080',
		  lightcyan: '#e0ffff',
		  lightgoldenrodyellow: '#fafad2',
		  lightgray: '#d3d3d3',
		  lightgreen: '#90ee90',
		  lightgrey: '#d3d3d3',
		  lightpink: '#ffb6c1',
		  lightsalmon: '#ffa07a',
		  lightseagreen: '#20b2aa',
		  lightskyblue: '#87cefa',
		  lightslategray: '#778899',
		  lightslategrey: '#778899',
		  lightsteelblue: '#b0c4de',
		  lightyellow: '#ffffe0',
		  lime: '#0f0',
		  limegreen: '#32cd32',
		  linen: '#faf0e6',
		  magenta: '#ff00ff',
		  maroon: '#800000',
		  mediumaquamarine: '#66cdaa',
		  mediumblue: '#0000cd',
		  mediumorchid: '#ba55d3',
		  mediumpurple: '#9370db',
		  mediumseagreen: '#3cb371',
		  mediumslateblue: '#7b68ee',
		  mediumspringgreen: '#00fa9a',
		  mediumturquoise: '#48d1cc',
		  mediumvioletred: '#c71585',
		  midnightblue: '#191970',
		  mintcream: '#f5fffa',
		  mistyrose: '#ffe4e1',
		  moccasin: '#ffe4b5',
		  navajowhite: '#ffdead',
		  navy: '#000080',
		  oldlace: '#fdf5e6',
		  olive: '#808000',
		  olivedrab: '#6b8e23',
		  orange: '#ffa500',
		  orangered: '#ff4500',
		  orchid: '#da70d6',
		  palegoldenrod: '#eee8aa',
		  palegreen: '#98fb98',
		  paleturquoise: '#afeeee',
		  palevioletred: '#db7093',
		  papayawhip: '#ffefd5',
		  peachpuff: '#ffdab9',
		  peru: '#cd853f',
		  pink: '#ffc0cb',
		  plum: '#dda0dd',
		  powderblue: '#b0e0e6',
		  purple: '#800080',
		  rebeccapurple: '#663399',
		  red: '#f00',
		  rosybrown: '#bc8f8f',
		  royalblue: '#4169e1',
		  saddlebrown: '#8b4513',
		  salmon: '#fa8072',
		  sandybrown: '#f4a460',
		  seagreen: '#2e8b57',
		  seashell: '#fff5ee',
		  sienna: '#a0522d',
		  silver: '#c0c0c0',
		  skyblue: '#87ceeb',
		  slateblue: '#6a5acd',
		  slategray: '#708090',
		  slategrey: '#708090',
		  snow: '#fffafa',
		  springgreen: '#00ff7f',
		  steelblue: '#4682b4',
		  tan: '#d2b48c',
		  teal: '#008080',
		  thistle: '#d8bfd8',
		  tomato: '#ff6347',
		  turquoise: '#40e0d0',
		  violet: '#ee82ee',
		  wheat: '#f5deb3',
		  white: '#fff',
		  whitesmoke: '#f5f5f5',
		  yellow: '#ff0',
		  yellowgreen: '#9acd32'
		};

		var toHex = {};
		var toName = {};

		for (var name in COLORS) {
		  var hex = COLORS[name];
		  if (name.length < hex.length)
			toName[hex] = name;
		  else
			toHex[name] = hex;
		}

		var toHexPattern = new RegExp('(^| |,|\\))(' + Object.keys(toHex).join('|') + ')( |,|\\)|$)', 'ig');
		var toNamePattern = new RegExp('(' + Object.keys(toName).join('|') + ')([^a-f0-9]|$)', 'ig');

		function hexConverter(match, prefix, colorValue, suffix) {
		  return prefix + toHex[colorValue.toLowerCase()] + suffix;
		}

		function nameConverter(match, colorValue, suffix) {
		  return toName[colorValue.toLowerCase()] + suffix;
		}

		HexNameShortener.shorten = function (value) {
		  var hasHex = value.indexOf('#') > -1;
		  var shortened = value.replace(toHexPattern, hexConverter);

		  if (shortened != value)
			shortened = shortened.replace(toHexPattern, hexConverter);

		  return hasHex ? shortened.replace(toNamePattern, nameConverter) : shortened;
		};
		
		return HexNameShortener;
	};
	//#endregion
	
	//#region URL: /selectors/optimizers/simple
	modules['/selectors/optimizers/simple'] = function () {
		var CleanUp = require('/selectors/optimizers/clean-up');
		var Splitter = require('/utils/splitter');

		var RGB = require('/colors/rgb');
		var HSL = require('/colors/hsl');
		var HexNameShortener = require('/colors/hex-name-shortener');

		var processable = require('/properties/processable');

		var DEFAULT_ROUNDING_PRECISION = 2;
		var CHARSET_TOKEN = '@charset';
		var CHARSET_REGEXP = new RegExp('^' + CHARSET_TOKEN, 'i');

		function SimpleOptimizer(options) {
		  this.options = options;

		  var units = ['px', 'em', 'ex', 'cm', 'mm', 'in', 'pt', 'pc', '%'];
		  if (options.compatibility.units.rem)
			units.push('rem');
		  options.unitsRegexp = new RegExp('(^|\\s|\\(|,)0(?:' + units.join('|') + ')', 'g');

		  options.precision = {};
		  options.precision.value = options.roundingPrecision === undefined ?
			DEFAULT_ROUNDING_PRECISION :
			options.roundingPrecision;
		  options.precision.multiplier = Math.pow(10, options.precision.value);
		  options.precision.regexp = new RegExp('(\\d*\\.\\d{' + (options.precision.value + 1) + ',})px', 'g');

		  options.updateMetadata = this.options.advanced;
		}

		var valueMinifiers = {
		  'background': function (value) {
			return value == 'none' || value == 'transparent' ? '0 0' : value;
		  },
		  'border-*-radius': function (value) {
			if (value.indexOf('/') == -1)
			  return value;

			var parts = value.split(/\s*\/\s*/);
			if (parts[0] == parts[1])
			  return parts[0];
			else
			  return parts[0] + '/' + parts[1];
		  },
		  'filter': function (value) {
			if (value.indexOf('DXImageTransform') === value.lastIndexOf('DXImageTransform')) {
			  value = value.replace(/progid:DXImageTransform\.Microsoft\.(Alpha|Chroma)(\W)/, function (match, filter, suffix) {
				return filter.toLowerCase() + suffix;
			  });
			}

			return value
			  .replace(/,(\S)/g, ', $1')
			  .replace(/ ?= ?/g, '=');
		  },
		  'font': function (value) {
			var parts = value.split(' ');

			if (parts[1] != 'normal' && parts[1] != 'bold' && !/^[1-9]00/.test(parts[1]))
			  parts[0] = this['font-weight'](parts[0]);

			return parts.join(' ');
		  },
		  'font-weight': function (value) {
			if (value == 'normal')
			  return '400';
			else if (value == 'bold')
			  return '700';
			else
			  return value;
		  },
		  'outline': function (value) {
			return value == 'none' ? '0' : value;
		  }
		};

		function isNegative(value) {
		  var parts = new Splitter(',').split(value);
		  for (var i = 0, l = parts.length; i < l; i++) {
			if (parts[i][0] == '-' && parseFloat(parts[i]) < 0)
			  return true;
		  }

		  return false;
		}

		function zeroMinifier(_, value) {
		  if (value.indexOf('0') == -1)
			return value;

		  if (value.indexOf('-') > -1) {
			value = value
			  .replace(/([^\w\d\-]|^)\-0([^\.]|$)/g, '$10$2')
			  .replace(/([^\w\d\-]|^)\-0([^\.]|$)/g, '$10$2');
		  }

		  return value
			.replace(/(^|\s)0+([1-9])/g, '$1$2')
			.replace(/(^|\D)\.0+(\D|$)/g, '$10$2')
			.replace(/(^|\D)\.0+(\D|$)/g, '$10$2')
			.replace(/\.([1-9]*)0+(\D|$)/g, function(match, nonZeroPart, suffix) {
			  return (nonZeroPart.length > 0 ? '.' : '') + nonZeroPart + suffix;
			})
			.replace(/(^|\D)0\.(\d)/g, '$1.$2');
		}

		function zeroDegMinifier(_, value) {
		  if (value.indexOf('0deg') == -1)
			return value;

		  return value.replace(/\(0deg\)/g, '(0)');
		}

		function precisionMinifier(_, value, precisionOptions) {
		  if (precisionOptions.value === -1 || value.indexOf('.') === -1)
			return value;

		  return value
			.replace(precisionOptions.regexp, function(match, number) {
			  return Math.round(parseFloat(number) * precisionOptions.multiplier) / precisionOptions.multiplier + 'px';
			})
			.replace(/(\d)\.($|\D)/g, '$1$2');
		}

		function unitMinifier(_, value, unitsRegexp) {
		  return value.replace(unitsRegexp, '$1' + '0');
		}

		function multipleZerosMinifier(property, value) {
		  if (value.indexOf('0 0 0 0') == -1)
			return value;

		  if (property.indexOf('box-shadow') > -1)
			return value == '0 0 0 0' ? '0 0' : value;

		  return value.replace(/^0 0 0 0$/, '0');
		}

		function colorMininifier(property, value, compatibility) {
		  if (value.indexOf('#') === -1 && value.indexOf('rgb') == -1 && value.indexOf('hsl') == -1)
			return HexNameShortener.shorten(value);

		  value = value
			.replace(/rgb\((\-?\d+),(\-?\d+),(\-?\d+)\)/g, function (match, red, green, blue) {
			  return new RGB(red, green, blue).toHex();
			})
			.replace(/hsl\((-?\d+),(-?\d+)%?,(-?\d+)%?\)/g, function (match, hue, saturation, lightness) {
			  return new HSL(hue, saturation, lightness).toHex();
			})
			.replace(/(^|[^='"])#([0-9a-f]{6})/gi, function (match, prefix, color) {
			  if (color[0] == color[1] && color[2] == color[3] && color[4] == color[5])
				return prefix + '#' + color[0] + color[2] + color[4];
			  else
				return prefix + '#' + color;
			})
			.replace(/(rgb|rgba|hsl|hsla)\(([^\)]+)\)/g, function(match, colorFunction, colorDef) {
			  var tokens = colorDef.split(',');
			  var applies = colorFunction == 'hsl' || colorFunction == 'hsla' || tokens[0].indexOf('%') > -1;
			  if (!applies)
				return match;

			  if (tokens[1].indexOf('%') == -1)
				tokens[1] += '%';
			  if (tokens[2].indexOf('%') == -1)
				tokens[2] += '%';
			  return colorFunction + '(' + tokens.join(',') + ')';
			});

		  if (compatibility.colors.opacity) {
			value = value.replace(/(?:rgba|hsla)\(0,0%?,0%?,0\)/g, function (match) {
			  if (new Splitter(',').split(value).pop().indexOf('gradient(') > -1)
				return match;

			  return 'transparent';
			});
		  }

		  return HexNameShortener.shorten(value);
		}

		function spaceMinifier(property, value) {
		  if (property == 'filter' || value.indexOf(') ') == -1 || processable.implementedFor.test(property))
			return value;

		  return value.replace(/\) ((?![\+\-] )|$)/g, ')$1');
		}

		function reduce(body, options) {
		  var reduced = [];
		  var properties = [];
		  var newProperty;

		  for (var i = 0, l = body.length; i < l; i++) {
			var token = body[i];

			// FIXME: the check should be gone with #396
			if (token.value.indexOf('__ESCAPED_') === 0) {
			  reduced.push(token);
			  properties.push(token.value);
			  continue;
			}

			var firstColon = token.value.indexOf(':');
			var property = token.value.substring(0, firstColon);
			var value = token.value.substring(firstColon + 1);
			var important = false;

			if (!options.compatibility.properties.iePrefixHack && (property[0] == '_' || property[0] == '*'))
			  continue;

			if (value.indexOf('!important') > 0 || value.indexOf('! important') > 0) {
			  value = value.substring(0, value.indexOf('!')).trim();
			  important = true;
			}

			if (property.indexOf('padding') === 0 && isNegative(value))
			  continue;

			if (property.indexOf('border') === 0 && property.indexOf('radius') > 0)
			  value = valueMinifiers['border-*-radius'](value);

			if (valueMinifiers[property])
			  value = valueMinifiers[property](value);

			value = precisionMinifier(property, value, options.precision);
			value = zeroMinifier(property, value);
			value = zeroDegMinifier(property, value);
			value = unitMinifier(property, value, options.unitsRegexp);
			value = multipleZerosMinifier(property, value);
			value = colorMininifier(property, value, options.compatibility);

			if (!options.compatibility.properties.spaceAfterClosingBrace)
			  value = spaceMinifier(property, value);

			newProperty = property + ':' + value + (important ? '!important' : '');
			reduced.push({ value: newProperty, metadata: token.metadata });
			properties.push(newProperty);
		  }

		  return {
			tokenized: reduced,
			list: properties
		  };
		}

		SimpleOptimizer.prototype.optimize = function(tokens) {
		  var self = this;
		  var hasCharset = false;
		  var options = this.options;

		  function _optimize(tokens) {
			for (var i = 0, l = tokens.length; i < l; i++) {
			  var token = tokens[i];
			  // FIXME: why it's so?
			  if (!token)
				break;

			  if (token.kind == 'selector') {
				var newSelectors = CleanUp.selectors(token.value, !options.compatibility.selectors.ie7Hack, options.compatibility.selectors.adjacentSpace);
				token.value = newSelectors.tokenized;

				if (token.value.length === 0) {
				  tokens.splice(i, 1);
				  i--;
				  continue;
				}
				var newBody = reduce(token.body, self.options);
				token.body = newBody.tokenized;

				if (options.updateMetadata) {
				  token.metadata.body = newBody.list.join(';');
				  token.metadata.bodiesList = newBody.list;
				  token.metadata.selector = newSelectors.list.join(',');
				  token.metadata.selectorsList = newSelectors.list;
				}
			  } else if (token.kind == 'block') {
				token.value = CleanUp.block(token.value);
				if (token.isFlatBlock)
				  token.body = reduce(token.body, self.options).tokenized;
				else
				  _optimize(token.body);
			  } else if (token.kind == 'at-rule') {
				token.value = CleanUp.atRule(token.value);

				if (CHARSET_REGEXP.test(token.value)) {
				  if (hasCharset || token.value.indexOf(CHARSET_TOKEN) == -1) {
					tokens.splice(i, 1);
					i--;
				  } else {
					hasCharset = true;
					tokens.splice(i, 1);
					tokens.unshift({ kind: 'at-rule', value: token.value.replace(CHARSET_REGEXP, CHARSET_TOKEN) });
				  }
				}
			  }
			}
		  }

		  _optimize(tokens);
		};
		
		return SimpleOptimizer;
	};
	//#endregion
	
	//#region URL: /properties/token
	modules['/properties/token'] = function () {
		// Helper for tokenizing the contents of a CSS selector block

		var exports = (function() {
		  var createTokenPrototype = function (processable) {
			var important = '!important';

			// Constructor for tokens
			function Token (prop, p2, p3) {
			  this.prop = prop;
			  if (typeof(p2) === 'string') {
				this.value = p2;
				this.isImportant = p3;
			  }
			  else {
				this.value = processable[prop].defaultValue;
				this.isImportant = p2;
			  }
			}

			Token.prototype.prop = null;
			Token.prototype.value = null;
			Token.prototype.granularValues = null;
			Token.prototype.components = null;
			Token.prototype.position = null;
			Token.prototype.isImportant = false;
			Token.prototype.isDirty = false;
			Token.prototype.isShorthand = false;
			Token.prototype.isIrrelevant = false;
			Token.prototype.isReal = true;
			Token.prototype.isMarkedForDeletion = false;
			Token.prototype.metadata = null;

			// Tells if this token is a component of the other one
			Token.prototype.isComponentOf = function (other) {
			  if (!processable[this.prop] || !processable[other.prop])
				return false;
			  if (!(processable[other.prop].components instanceof Array) || !processable[other.prop].components.length)
				return false;

			  return processable[other.prop].components.indexOf(this.prop) >= 0;
			};

			// Clones a token
			Token.prototype.clone = function (isImportant) {
			  var token = new Token(this.prop, this.value, (typeof(isImportant) !== 'undefined' ? isImportant : this.isImportant));
			  return token;
			};

			// Creates an irrelevant token with the same prop
			Token.prototype.cloneIrrelevant = function (isImportant) {
			  var token = Token.makeDefault(this.prop, (typeof(isImportant) !== 'undefined' ? isImportant : this.isImportant));
			  token.isIrrelevant = true;
			  return token;
			};

			// Creates an array of property tokens with their default values
			Token.makeDefaults = function (props, important) {
			  return props.map(function(prop) {
				return new Token(prop, important);
			  });
			};

			// Parses one CSS property declaration into a token
			Token.tokenizeOne = function (fullProp) {
			  // Find first colon
			  var colonPos = fullProp.value.indexOf(':');

			  if (colonPos < 0) {
				// This property doesn't have a colon, it's invalid. Let's keep it intact anyway.
				return new Token('', fullProp.value);
			  }

			  // Parse parts of the property
			  var prop = fullProp.value.substr(0, colonPos).trim();
			  var value = fullProp.value.substr(colonPos + 1).trim();
			  var isImportant = false;
			  var importantPos = value.indexOf(important);

			  // Check if the property is important
			  if (importantPos >= 1 && importantPos === value.length - important.length) {
				value = value.substr(0, importantPos).trim();
				isImportant = true;
			  }

			  // Return result
			  var result = new Token(prop, value, isImportant);

			  // If this is a shorthand, break up its values
			  // NOTE: we need to do this for all shorthands because otherwise we couldn't remove default values from them
			  if (processable[prop] && processable[prop].isShorthand) {
				result.isShorthand = true;
				result.components = processable[prop].breakUp(result);
				result.isDirty = true;
			  }

			  result.metadata = fullProp.metadata;

			  return result;
			};

			// Breaks up a string of CSS property declarations into tokens so that they can be handled more easily
			Token.tokenize = function (input) {
			  // Split the input by semicolons and parse the parts
			  var tokens = input.map(Token.tokenizeOne);
			  return tokens;
			};

			// Transforms tokens back into CSS properties
			Token.detokenize = function (tokens) {
			  // If by mistake the input is not an array, make it an array
			  if (!(tokens instanceof Array)) {
				tokens = [tokens];
			  }

			  var tokenized = [];
			  var list = [];

			  // This step takes care of putting together the components of shorthands
			  // NOTE: this is necessary to do for every shorthand, otherwise we couldn't remove their default values
			  for (var i = 0; i < tokens.length; i++) {
				var t = tokens[i];
				if (t.isShorthand && t.isDirty) {
				  var news = processable[t.prop].putTogether(t.prop, t.components, t.isImportant);
				  Array.prototype.splice.apply(tokens, [i, 1].concat(news));
				  t.isDirty = false;
				  i--;
				  continue;
				}

				// FIXME: the check should be gone with #396
				var property = t.prop === '' && t.value.indexOf('__ESCAPED_') === 0 ?
				  t.value :
				  t.prop + ':' + t.value + (t.isImportant ? important : '');

				// FIXME: to be fixed with #429
				property = property.replace(/\) /g, ')');

				tokenized.push({ value: property, metadata: t.metadata || {} });
				list.push(property);
			  }

			  return {
				list: list,
				tokenized: tokenized
			  };
			};

			// Gets the final (detokenized) length of the given tokens
			Token.getDetokenizedLength = function (tokens) {
			  // If by mistake the input is not an array, make it an array
			  if (!(tokens instanceof Array)) {
				tokens = [tokens];
			  }

			  var result = 0;

			  // This step takes care of putting together the components of shorthands
			  // NOTE: this is necessary to do for every shorthand, otherwise we couldn't remove their default values
			  for (var i = 0; i < tokens.length; i++) {
				var t = tokens[i];
				if (t.isShorthand && t.isDirty) {
				  var news = processable[t.prop].putTogether(t.prop, t.components, t.isImportant);
				  Array.prototype.splice.apply(tokens, [i, 1].concat(news));
				  t.isDirty = false;
				  i--;
				  continue;
				}

				if (t.prop) {
				  result += t.prop.length + 1;
				}
				if (t.value) {
				  result += t.value.length;
				}
				if (t.isImportant) {
				  result += important.length;
				}
			  }

			  return result;
			};

			return Token;
		  };

		  return {
			createTokenPrototype: createTokenPrototype
		  };

		})();
		
		return exports;
	};
	//#endregion
	
	//#region URL: /properties/validator
	modules['/properties/validator'] = function () {
		// Validates various CSS property values

		var Splitter = require('/utils/splitter');

		var exports = (function () {
		  // Regexes used for stuff
		  var widthKeywords = ['thin', 'thick', 'medium', 'inherit', 'initial'];
		  var allUnits = ['px', '%', 'em', 'rem', 'in', 'cm', 'mm', 'ex', 'pt', 'pc', 'vw', 'vh', 'vmin', 'vmax'];
		  var cssUnitRegexStr = '(\\-?\\.?\\d+\\.?\\d*(' + allUnits.join('|') + '|)|auto|inherit)';
		  var cssCalcRegexStr = '(\\-moz\\-|\\-webkit\\-)?calc\\([^\\)]+\\)';
		  var cssFunctionNoVendorRegexStr = '[A-Z]+(\\-|[A-Z]|[0-9])+\\(([A-Z]|[0-9]|\\ |\\,|\\#|\\+|\\-|\\%|\\.|\\(|\\))*\\)';
		  var cssFunctionVendorRegexStr = '\\-(\\-|[A-Z]|[0-9])+\\(([A-Z]|[0-9]|\\ |\\,|\\#|\\+|\\-|\\%|\\.|\\(|\\))*\\)';
		  var cssVariableRegexStr = 'var\\(\\-\\-[^\\)]+\\)';
		  var cssFunctionAnyRegexStr = '(' + cssVariableRegexStr + '|' + cssFunctionNoVendorRegexStr + '|' + cssFunctionVendorRegexStr + ')';
		  var cssUnitOrCalcRegexStr = '(' + cssUnitRegexStr + '|' + cssCalcRegexStr + ')';
		  var cssUnitAnyRegexStr = '(none|' + widthKeywords.join('|') + '|' + cssUnitRegexStr + '|' + cssVariableRegexStr + '|' + cssFunctionNoVendorRegexStr + '|' + cssFunctionVendorRegexStr + ')';

		  var cssFunctionNoVendorRegex = new RegExp('^' + cssFunctionNoVendorRegexStr + '$', 'i');
		  var cssFunctionVendorRegex = new RegExp('^' + cssFunctionVendorRegexStr + '$', 'i');
		  var cssVariableRegex = new RegExp('^' + cssVariableRegexStr + '$', 'i');
		  var cssFunctionAnyRegex = new RegExp('^' + cssFunctionAnyRegexStr + '$', 'i');
		  var cssUnitRegex = new RegExp('^' + cssUnitRegexStr + '$', 'i');
		  var cssUnitOrCalcRegex = new RegExp('^' + cssUnitOrCalcRegexStr + '$', 'i');
		  var cssUnitAnyRegex = new RegExp('^' + cssUnitAnyRegexStr + '$', 'i');

		  var backgroundRepeatKeywords = ['repeat', 'no-repeat', 'repeat-x', 'repeat-y', 'inherit'];
		  var backgroundAttachmentKeywords = ['inherit', 'scroll', 'fixed', 'local'];
		  var backgroundPositionKeywords = ['center', 'top', 'bottom', 'left', 'right'];
		  var backgroundSizeKeywords = ['contain', 'cover'];
		  var backgroundBoxKeywords = ['border-box', 'content-box', 'padding-box'];
		  var listStyleTypeKeywords = ['armenian', 'circle', 'cjk-ideographic', 'decimal', 'decimal-leading-zero', 'disc', 'georgian', 'hebrew', 'hiragana', 'hiragana-iroha', 'inherit', 'katakana', 'katakana-iroha', 'lower-alpha', 'lower-greek', 'lower-latin', 'lower-roman', 'none', 'square', 'upper-alpha', 'upper-latin', 'upper-roman'];
		  var listStylePositionKeywords = ['inside', 'outside', 'inherit'];
		  var outlineStyleKeywords = ['auto', 'inherit', 'hidden', 'none', 'dotted', 'dashed', 'solid', 'double', 'groove', 'ridge', 'inset', 'outset'];

		  var compatibleCssUnitRegex;
		  var compatibleCssUnitAnyRegex;

		  var validator = {
			// FIXME: we need a proper OO here
			setCompatibility: function (compatibility) {
			  if (compatibility.units.rem) {
				compatibleCssUnitRegex = cssUnitRegex;
				compatibleCssUnitAnyRegex = cssUnitAnyRegex;
				return;
			  }

			  var validUnits = allUnits.slice(0).filter(function (value) {
				return value != 'rem';
			  });

			  var compatibleCssUnitRegexStr = '(\\-?\\.?\\d+\\.?\\d*(' + validUnits.join('|') + ')|auto|inherit)';
			  compatibleCssUnitRegex = new RegExp('^' + compatibleCssUnitRegexStr + '$', 'i');
			  compatibleCssUnitAnyRegex = new RegExp('^(none|' + widthKeywords.join('|') + '|' + compatibleCssUnitRegexStr + '|' + cssVariableRegexStr + '|' + cssFunctionNoVendorRegexStr + '|' + cssFunctionVendorRegexStr + ')$', 'i');
			},

			isValidHexColor: function (s) {
			  return (s.length === 4 || s.length === 7) && s[0] === '#';
			},
			isValidRgbaColor: function (s) {
			  s = s.split(' ').join('');
			  return s.length > 0 && s.indexOf('rgba(') === 0 && s.indexOf(')') === s.length - 1;
			},
			isValidHslaColor: function (s) {
			  s = s.split(' ').join('');
			  return s.length > 0 && s.indexOf('hsla(') === 0 && s.indexOf(')') === s.length - 1;
			},
			isValidNamedColor: function (s) {
			  // We don't really check if it's a valid color value, but allow any letters in it
			  return s !== 'auto' && (s === 'transparent' || s === 'inherit' || /^[a-zA-Z]+$/.test(s));
			},
			isValidVariable: function(s) {
			  return cssVariableRegex.test(s);
			},
			isValidColor: function (s) {
			  return validator.isValidNamedColor(s) || validator.isValidHexColor(s) || validator.isValidRgbaColor(s) || validator.isValidHslaColor(s) || validator.isValidVariable(s);
			},
			isValidUrl: function (s) {
			  // NOTE: at this point all URLs are replaced with placeholders by clean-css, so we check for those placeholders
			  return s.indexOf('__ESCAPED_URL_CLEAN_CSS') === 0;
			},
			isValidUnit: function (s) {
			  return cssUnitAnyRegex.test(s);
			},
			isValidUnitWithoutFunction: function (s) {
			  return cssUnitRegex.test(s);
			},
			isValidAndCompatibleUnit: function (s) {
			  return compatibleCssUnitAnyRegex.test(s);
			},
			isValidAndCompatibleUnitWithoutFunction: function (s) {
			  return compatibleCssUnitRegex.test(s);
			},
			isValidFunctionWithoutVendorPrefix: function (s) {
			  return cssFunctionNoVendorRegex.test(s);
			},
			isValidFunctionWithVendorPrefix: function (s) {
			  return cssFunctionVendorRegex.test(s);
			},
			isValidFunction: function (s) {
			  return cssFunctionAnyRegex.test(s);
			},
			isValidBackgroundRepeat: function (s) {
			  return backgroundRepeatKeywords.indexOf(s) >= 0 || validator.isValidVariable(s);
			},
			isValidBackgroundAttachment: function (s) {
			  return backgroundAttachmentKeywords.indexOf(s) >= 0 || validator.isValidVariable(s);
			},
			isValidBackgroundBox: function (s) {
			  return backgroundBoxKeywords.indexOf(s) >= 0 || validator.isValidVariable(s);
			},
			isValidBackgroundPositionPart: function (s) {
			  return backgroundPositionKeywords.indexOf(s) >= 0 || cssUnitOrCalcRegex.test(s) || validator.isValidVariable(s);
			},
			isValidBackgroundPosition: function (s) {
			  if (s === 'inherit')
				return true;

			  var parts = s.split(' ');
			  for (var i = 0, l = parts.length; i < l; i++) {
				if (parts[i] === '')
				  continue;
				if (validator.isValidBackgroundPositionPart(parts[i]) || validator.isValidVariable(parts[i]))
				  continue;

				return false;
			  }

			  return true;
			},
			isValidBackgroundSizePart: function(s) {
			  return backgroundSizeKeywords.indexOf(s) >= 0 || cssUnitRegex.test(s) || validator.isValidVariable(s);
			},
			isValidBackgroundPositionAndSize: function(s) {
			  if (s.indexOf('/') < 0)
				return false;

			  var twoParts = new Splitter('/').split(s);
			  return validator.isValidBackgroundSizePart(twoParts.pop()) && validator.isValidBackgroundPositionPart(twoParts.pop());
			},
			isValidListStyleType: function (s) {
			  return listStyleTypeKeywords.indexOf(s) >= 0 || validator.isValidVariable(s);
			},
			isValidListStylePosition: function (s) {
			  return listStylePositionKeywords.indexOf(s) >= 0 || validator.isValidVariable(s);
			},
			isValidOutlineColor: function (s) {
			  return s === 'invert' || validator.isValidColor(s) || validator.isValidVendorPrefixedValue(s);
			},
			isValidOutlineStyle: function (s) {
			  return outlineStyleKeywords.indexOf(s) >= 0 || validator.isValidVariable(s);
			},
			isValidOutlineWidth: function (s) {
			  return validator.isValidUnit(s) || widthKeywords.indexOf(s) >= 0 || validator.isValidVariable(s);
			},
			isValidVendorPrefixedValue: function (s) {
			  return /^-([A-Za-z0-9]|-)*$/gi.test(s);
			},
			areSameFunction: function (a, b) {
			  if (!validator.isValidFunction(a) || !validator.isValidFunction(b))
				return false;

			  var f1name = a.substring(0, a.indexOf('('));
			  var f2name = b.substring(0, b.indexOf('('));

			  return f1name === f2name;
			}
		  };

		  return validator;
		})();
		
		return exports;
	};
	//#endregion
	
	//#region URL: /properties/processable
	modules['/properties/processable'] = function () {
		// Contains the interpretation of CSS properties, as used by the property optimizer

		var exports = (function () {
		  var tokenModule = require('/properties/token');
		  var validator = require('/properties/validator');
		  var Splitter = require('/utils/splitter');

		  // Functions that decide what value can override what.
		  // The main purpose is to disallow removing CSS fallbacks.
		  // A separate implementation is needed for every different kind of CSS property.
		  // -----
		  // The generic idea is that properties that have wider browser support are 'more understandable'
		  // than others and that 'less understandable' values can't override more understandable ones.
		  var canOverride = {
			// Use when two tokens of the same property can always be merged
			always: function () {
			  // NOTE: We could have (val1, val2) parameters here but jshint complains because we don't use them
			  return true;
			},
			// Use when two tokens of the same property can only be merged if they have the same value
			sameValue: function(val1, val2) {
			  return val1 === val2;
			},
			sameFunctionOrValue: function(val1, val2) {
			  // Functions with the same name can override each other
			  if (validator.areSameFunction(val1, val2)) {
				return true;
			  }

			  return val1 === val2;
			},
			// Use for properties containing CSS units (margin-top, padding-left, etc.)
			unit: function(val1, val2) {
			  // The idea here is that 'more understandable' values override 'less understandable' values, but not vice versa
			  // Understandability: (unit without functions) > (same functions | standard functions) > anything else
			  // NOTE: there is no point in having different vendor-specific functions override each other or standard functions,
			  //       or having standard functions override vendor-specific functions, but standard functions can override each other
			  // NOTE: vendor-specific property values are not taken into consideration here at the moment
			  if (validator.isValidAndCompatibleUnitWithoutFunction(val1) && !validator.isValidAndCompatibleUnitWithoutFunction(val2))
				return false;

			  if (validator.isValidUnitWithoutFunction(val2))
				return true;
			  if (validator.isValidUnitWithoutFunction(val1))
				return false;

			  // Standard non-vendor-prefixed functions can override each other
			  if (validator.isValidFunctionWithoutVendorPrefix(val2) && validator.isValidFunctionWithoutVendorPrefix(val1)) {
				return true;
			  }

			  // Functions with the same name can override each other; same values can override each other
			  return canOverride.sameFunctionOrValue(val1, val2);
			},
			// Use for color properties (color, background-color, border-color, etc.)
			color: function(val1, val2) {
			  // The idea here is that 'more understandable' values override 'less understandable' values, but not vice versa
			  // Understandability: (hex | named) > (rgba | hsla) > (same function name) > anything else
			  // NOTE: at this point rgb and hsl are replaced by hex values by clean-css

			  // (hex | named)
			  if (validator.isValidNamedColor(val2) || validator.isValidHexColor(val2))
				return true;
			  if (validator.isValidNamedColor(val1) || validator.isValidHexColor(val1))
				return false;

			  // (rgba|hsla)
			  if (validator.isValidRgbaColor(val2) || validator.isValidHslaColor(val2))
				return true;
			  if (validator.isValidRgbaColor(val1) || validator.isValidHslaColor(val1))
				return false;

			  // Functions with the same name can override each other; same values can override each other
			  return canOverride.sameFunctionOrValue(val1, val2);
			},
			// Use for background-image
			backgroundImage: function(val1, val2) {
			  // The idea here is that 'more understandable' values override 'less understandable' values, but not vice versa
			  // Understandability: (none | url | inherit) > (same function) > (same value)

			  // (none | url)
			  if (val2 === 'none' || val2 === 'inherit' || validator.isValidUrl(val2))
				return true;
			  if (val1 === 'none' || val1 === 'inherit' || validator.isValidUrl(val1))
				return false;

			  // Functions with the same name can override each other; same values can override each other
			  return canOverride.sameFunctionOrValue(val1, val2);
			},
			border: function(val1, val2) {
			  var brokenUp1 = breakUp.border(Token.tokenizeOne({ value: val1 }));
			  var brokenUp2 = breakUp.border(Token.tokenizeOne({ value: val2 }));

			  return canOverride.color(brokenUp1[2].value, brokenUp2[2].value);
			}
		  };
		  canOverride = Object.freeze(canOverride);

		  // Functions for breaking up shorthands to components
		  var breakUp = {};
		  breakUp.takeCareOfFourValues = function (splitfunc) {
			return function (token) {
			  var descriptor = processable[token.prop];
			  var result = [];
			  var splitval = splitfunc(token.value);

			  if (splitval.length === 0 || (splitval.length < descriptor.components.length && descriptor.components.length > 4)) {
				// This token is malformed and we have no idea how to fix it. So let's just keep it intact
				return [token];
			  }

			  // Fix those that we do know how to fix
			  if (splitval.length < descriptor.components.length && splitval.length < 2) {
				// foo{margin:1px} -> foo{margin:1px 1px}
				splitval[1] = splitval[0];
			  }
			  if (splitval.length < descriptor.components.length && splitval.length < 3) {
				// foo{margin:1px 2px} -> foo{margin:1px 2px 1px}
				splitval[2] = splitval[0];
			  }
			  if (splitval.length < descriptor.components.length && splitval.length < 4) {
				// foo{margin:1px 2px 3px} -> foo{margin:1px 2px 3px 2px}
				splitval[3] = splitval[1];
			  }

			  // Now break it up to its components
			  for (var i = 0; i < descriptor.components.length; i++) {
				var t = new Token(descriptor.components[i], splitval[i], token.isImportant);
				result.push(t);
			  }

			  return result;
			};
		  };
		  // Use this when you simply want to break up four values along spaces
		  breakUp.fourBySpaces = breakUp.takeCareOfFourValues(function (val) {
			return new Splitter(' ').split(val).filter(function (v) { return v; });
		  });
		  // Breaks up a background property value
		  breakUp.commaSeparatedMulitpleValues = function (splitfunc) {
			return function (token) {
			  if (token.value.indexOf(',') === -1)
				return splitfunc(token);

			  var values = new Splitter(',').split(token.value);
			  var components = [];

			  // TODO: we should be rather clonging elements than reusing them!
			  for (var i = 0, l = values.length; i < l; i++) {
				token.value = values[i];
				components.push(splitfunc(token));
			  }

			  token.value = values.join(',');

			  for (var j = 0, m = components[0].length; j < m; j++) {
				for (var k = 0, n = components.length, newValues = []; k < n; k++) {
				  newValues.push(components[k][j].value);
				}

				components[0][j].value = newValues.join(',');
			  }

			  return components[0];
			};
		  };
		  breakUp.background = function (token) {
			// Default values
			var result = Token.makeDefaults(['background-image', 'background-position', 'background-size', 'background-repeat', 'background-attachment', 'background-origin', 'background-clip', 'background-color'], token.isImportant);
			var image = result[0];
			var position = result[1];
			var size = result[2];
			var repeat = result[3];
			var attachment = result[4];
			var origin = result[5];
			var clip = result[6];
			var color = result[7];
			var positionSet = false;
			var clipSet = false;
			var originSet = false;
			var repeatSet = false;

			// Take care of inherit
			if (token.value === 'inherit') {
			  // NOTE: 'inherit' is not a valid value for background-attachment so there we'll leave the default value
			  color.value = image.value =  repeat.value = position.value = size.value = attachment.value = origin.value = clip.value = 'inherit';
			  return result;
			}

			// Break the background up into parts
			var parts = new Splitter(' ').split(token.value);
			if (parts.length === 0)
			  return result;

			// Iterate over all parts and try to fit them into positions
			for (var i = parts.length - 1; i >= 0; i--) {
			  var currentPart = parts[i];

			  if (validator.isValidBackgroundAttachment(currentPart)) {
				attachment.value = currentPart;
			  } else if (validator.isValidBackgroundBox(currentPart)) {
				if (clipSet) {
				  origin.value = currentPart;
				  originSet = true;
				} else {
				  clip.value = currentPart;
				  clipSet = true;
				}
			  } else if (validator.isValidBackgroundRepeat(currentPart)) {
				if (repeatSet) {
				  repeat.value = currentPart + ' ' + repeat.value;
				} else {
				  repeat.value = currentPart;
				  repeatSet = true;
				}
			  } else if (validator.isValidBackgroundPositionPart(currentPart) || validator.isValidBackgroundSizePart(currentPart)) {
				if (i > 0) {
				  var previousPart = parts[i - 1];

				  if (previousPart.indexOf('/') > 0) {
					var twoParts = new Splitter('/').split(previousPart);
					size.value = twoParts.pop() + ' ' + currentPart;
					parts[i - 1] = twoParts.pop();
				  } else if (i > 1 && parts[i - 2] == '/') {
					size.value = previousPart + ' ' + currentPart;
					i -= 2;
				  } else if (parts[i - 1] == '/') {
					size.value = currentPart;
				  } else {
					position.value = currentPart + (positionSet ? ' ' + position.value : '');
					positionSet = true;
				  }
				} else {
				  position.value = currentPart + (positionSet ? ' ' + position.value : '');
				  positionSet = true;
				}
			  } else if (validator.isValidBackgroundPositionAndSize(currentPart)) {
				var sizeValue = new Splitter('/').split(currentPart);
				size.value = sizeValue.pop();
				position.value = sizeValue.pop();
			  } else if ((color.value == processable[color.prop].defaultValue || color.value == 'none') && validator.isValidColor(currentPart)) {
				color.value = currentPart;
			  } else if (validator.isValidUrl(currentPart) || validator.isValidFunction(currentPart)) {
				image.value = currentPart;
			  }
			}

			if (clipSet && !originSet)
			  origin.value = clip.value;

			return result;
		  };
		  // Breaks up a list-style property value
		  breakUp.listStyle = function (token) {
			// Default values
			var result = Token.makeDefaults(['list-style-type', 'list-style-position', 'list-style-image'], token.isImportant);
			var type = result[0], position = result[1], image = result[2];

			if (token.value === 'inherit') {
			  type.value = position.value = image.value = 'inherit';
			  return result;
			}

			var parts = new Splitter(' ').split(token.value);
			var ci = 0;

			// Type
			if (ci < parts.length && validator.isValidListStyleType(parts[ci])) {
			  type.value = parts[ci];
			  ci++;
			}
			// Position
			if (ci < parts.length && validator.isValidListStylePosition(parts[ci])) {
			  position.value = parts[ci];
			  ci++;
			}
			// Image
			if (ci < parts.length) {
			  image.value = parts.splice(ci, parts.length - ci + 1).join(' ');
			}

			return result;
		  };

		  breakUp._widthStyleColor = function(token, prefix, order) {
			// Default values
			var components = order.map(function(prop) {
			  return prefix + '-' + prop;
			});
			var result = Token.makeDefaults(components, token.isImportant);
			var color = result[order.indexOf('color')];
			var style = result[order.indexOf('style')];
			var width = result[order.indexOf('width')];

			// Take care of inherit
			if (token.value === 'inherit' || token.value === 'inherit inherit inherit') {
			  color.value = style.value = width.value = 'inherit';
			  return result;
			}

			// NOTE: usually users don't follow the required order of parts in this shorthand,
			// so we'll try to parse it caring as little about order as possible

			var parts = new Splitter(' ').split(token.value), w;

			if (parts.length === 0) {
			  return result;
			}

			if (parts.length >= 1) {
			  // Try to find -width, excluding inherit because that can be anything
			  w = parts.filter(function(p) { return p !== 'inherit' && validator.isValidOutlineWidth(p); });
			  if (w.length) {
				width.value = w[0];
				parts.splice(parts.indexOf(w[0]), 1);
			  }
			}
			if (parts.length >= 1) {
			  // Try to find -style, excluding inherit because that can be anything
			  w = parts.filter(function(p) { return p !== 'inherit' && validator.isValidOutlineStyle(p); });
			  if (w.length) {
				style.value = w[0];
				parts.splice(parts.indexOf(w[0]), 1);
			  }
			}
			if (parts.length >= 1) {
			  // Find -color but this time can catch inherit
			  w = parts.filter(function(p) { return validator.isValidOutlineColor(p); });
			  if (w.length) {
				color.value = w[0];
				parts.splice(parts.indexOf(w[0]), 1);
			  }
			}

			return result;
		  };

		  breakUp.outline = function(token) {
			return breakUp._widthStyleColor(token, 'outline', ['color', 'style', 'width']);
		  };

		  breakUp.border = function(token) {
			return breakUp._widthStyleColor(token, 'border', ['width', 'style', 'color']);
		  };

		  breakUp.borderRadius = function(token) {
			var parts = token.value.split('/');
			if (parts.length == 1)
			  return breakUp.fourBySpaces(token);

			var horizontalPart = token.clone();
			var verticalPart = token.clone();

			horizontalPart.value = parts[0];
			verticalPart.value = parts[1];

			var horizontalBreakUp = breakUp.fourBySpaces(horizontalPart);
			var verticalBreakUp = breakUp.fourBySpaces(verticalPart);

			for (var i = 0; i < 4; i++) {
			  horizontalBreakUp[i].value = [horizontalBreakUp[i].value, verticalBreakUp[i].value];
			}

			return horizontalBreakUp;
		  };

		  // Contains functions that can put together shorthands from their components
		  // NOTE: correct order of tokens is assumed inside these functions!
		  var putTogether = {
			// Use this for properties which have four unit values (margin, padding, etc.)
			// NOTE: optimizes to shorter forms too (that only specify 1, 2, or 3 values)
			fourUnits: function (prop, tokens, isImportant) {
			  // See about irrelevant tokens
			  // NOTE: This will enable some crazy optimalizations for us.
			  if (tokens[0].isIrrelevant)
				tokens[0].value = tokens[2].value;
			  if (tokens[2].isIrrelevant)
				tokens[2].value = tokens[0].value;
			  if (tokens[1].isIrrelevant)
				tokens[1].value = tokens[3].value;
			  if (tokens[3].isIrrelevant)
				tokens[3].value = tokens[1].value;

			  if (tokens[0].isIrrelevant && tokens[2].isIrrelevant) {
				if (tokens[1].value === tokens[3].value)
				  tokens[0].value = tokens[2].value = tokens[1].value;
				else
				  tokens[0].value = tokens[2].value = '0';
			  }
			  if (tokens[1].isIrrelevant && tokens[3].isIrrelevant) {
				if (tokens[0].value === tokens[2].value)
				  tokens[1].value = tokens[3].value = tokens[0].value;
				else
				  tokens[1].value = tokens[3].value = '0';
			  }

			  var result = new Token(prop, tokens[0].value, isImportant);
			  result.granularValues = [];
			  result.granularValues[tokens[0].prop] = tokens[0].value;
			  result.granularValues[tokens[1].prop] = tokens[1].value;
			  result.granularValues[tokens[2].prop] = tokens[2].value;
			  result.granularValues[tokens[3].prop] = tokens[3].value;

			  // If all of them are irrelevant
			  if (tokens[0].isIrrelevant && tokens[1].isIrrelevant && tokens[2].isIrrelevant && tokens[3].isIrrelevant) {
				result.value = processable[prop].shortestValue || processable[prop].defaultValue;
				return result;
			  }

			  // 1-value short form: all four components are equal
			  if (tokens[0].value === tokens[1].value && tokens[0].value === tokens[2].value && tokens[0].value === tokens[3].value) {
				return result;
			  }
			  result.value += ' ' + tokens[1].value;
			  // 2-value short form: first and third; second and fourth values are equal
			  if (tokens[0].value === tokens[2].value && tokens[1].value === tokens[3].value) {
				return result;
			  }
			  result.value += ' ' + tokens[2].value;
			  // 3-value short form: second and fourth values are equal
			  if (tokens[1].value === tokens[3].value) {
				return result;
			  }
			  // 4-value form (none of the above optimalizations could be accomplished)
			  result.value += ' ' + tokens[3].value;
			  return result;
			},
			// Puts together the components by spaces and omits default values (this is the case for most shorthands)
			bySpacesOmitDefaults: function (prop, tokens, isImportant, meta) {
			  var result = new Token(prop, '', isImportant);

			  // Get irrelevant tokens
			  var irrelevantTokens = tokens.filter(function (t) { return t.isIrrelevant; });

			  // If every token is irrelevant, return shortest possible value, fallback to default value
			  if (irrelevantTokens.length === tokens.length) {
				result.isIrrelevant = true;
				result.value = processable[prop].shortestValue || processable[prop].defaultValue;
				return result;
			  }

			  // This will be the value of the shorthand if all the components are default
			  var valueIfAllDefault = processable[prop].defaultValue;

			  // Go through all tokens and concatenate their values as necessary
			  for (var i = 0; i < tokens.length; i++) {
				var token = tokens[i];
				var definition = processable[token.prop] && processable[token.prop];

				// Set granular value so that other parts of the code can use this for optimalization opportunities
				result.granularValues = result.granularValues || { };
				result.granularValues[token.prop] = token.value;

				// Use irrelevant tokens for optimalization opportunity
				if (token.isIrrelevant) {
				  // Get shortest possible value, fallback to default value
				  var tokenShortest = processable[token.prop].shortestValue || processable[token.prop].defaultValue;
				  // If the shortest possible value of this token is shorter than the default value of the shorthand, use it instead
				  if (tokenShortest.length < valueIfAllDefault.length) {
					valueIfAllDefault = tokenShortest;
				  }
				}

				// merge with previous if possible
				if (definition.mergeWithPrevious && token.value === tokens[i - 1].value)
				  continue;

				// omit irrelevant value
				if (token.isIrrelevant)
				  continue;

				// omit default value unless mergable with previous and it wasn't default
				if (definition.defaultValue === token.value)
				  if (!definition.mergeWithPrevious || tokens[i - 1].value === processable[tokens[i - 1].prop].defaultValue)
					continue;

				if (meta && meta.partsCount && meta.position < meta.partsCount - 1 && definition.multiValueLastOnly)
				  continue;

				var requiresPreceeding = definition.shorthandFollows;
				if (requiresPreceeding && (tokens[i - 1].value == processable[requiresPreceeding].defaultValue)) {
				  result.value += ' ' + tokens[i - 1].value;
				}

				result.value += (definition.prefixShorthandValueWith || ' ') + token.value;
			  }

			  result.value = result.value.trim();
			  if (!result.value) {
				result.value = valueIfAllDefault;
			  }

			  return result;
			},
			commaSeparatedMulitpleValues: function (assembleFunction) {
			  return function(prop, tokens, isImportant) {
				var tokenSplitLengths = tokens.map(function (token) {
				  return new Splitter(',').split(token.value).length;
				});
				var partsCount = Math.max.apply(Math, tokenSplitLengths);

				if (partsCount == 1)
				  return assembleFunction(prop, tokens, isImportant);

				var merged = [];

				for (var i = 0; i < partsCount; i++) {
				  merged.push([]);

				  for (var j = 0; j < tokens.length; j++) {
					var split = new Splitter(',').split(tokens[j].value);
					merged[i].push(split[i] || split[0]);
				  }
				}

				var mergedValues = [];
				var firstProcessed;
				for (i = 0; i < partsCount; i++) {
				  var newTokens = [];
				  for (var k = 0, n = merged[i].length; k < n; k++) {
					var newToken = tokens[k].clone();
					newToken.value = merged[i][k];
					newTokens.push(newToken);
				  }

				  var meta = {
					partsCount: partsCount,
					position: i
				  };
				  var processed = assembleFunction(prop, newTokens, isImportant, meta);
				  mergedValues.push(processed.value);

				  if (!firstProcessed)
					firstProcessed = processed;
				}

				firstProcessed.value = mergedValues.join(',');
				return firstProcessed;
			  };
			},
			// Handles the cases when some or all the fine-grained properties are set to inherit
			takeCareOfInherit: function (innerFunc) {
			  return function (prop, tokens, isImportant, meta) {
				// Filter out the inheriting and non-inheriting tokens in one iteration
				var inheritingTokens = [];
				var nonInheritingTokens = [];
				var result2Shorthandable = [];
				var i;
				for (i = 0; i < tokens.length; i++) {
				  if (tokens[i].value === 'inherit') {
					inheritingTokens.push(tokens[i]);

					// Indicate that this property is irrelevant and its value can safely be set to anything else
					var r2s = new Token(tokens[i].prop, tokens[i].isImportant);
					r2s.isIrrelevant = true;
					result2Shorthandable.push(r2s);
				  } else {
					nonInheritingTokens.push(tokens[i]);
					result2Shorthandable.push(tokens[i]);
				  }
				}

				if (nonInheritingTokens.length === 0) {
				  // When all the tokens are 'inherit'
				  return new Token(prop, 'inherit', isImportant);
				} else if (inheritingTokens.length > 0) {
				  // When some (but not all) of the tokens are 'inherit'

				  // Result 1. Shorthand just the inherit values and have it overridden with the non-inheriting ones
				  var result1 = [new Token(prop, 'inherit', isImportant)].concat(nonInheritingTokens);

				  // Result 2. Shorthand every non-inherit value and then have it overridden with the inheriting ones
				  var result2 = [innerFunc(prop, result2Shorthandable, isImportant, meta)].concat(inheritingTokens);

				  // Return whichever is shorter
				  var dl1 = Token.getDetokenizedLength(result1);
				  var dl2 = Token.getDetokenizedLength(result2);

				  return dl1 < dl2 ? result1 : result2;
				} else {
				  // When none of tokens are 'inherit'
				  return innerFunc(prop, tokens, isImportant, meta);
				}
			  };
			},
			borderRadius: function (prop, tokens, isImportant) {
			  var verticalTokens = [];
			  var newTokens = [];

			  for (var i = 0, l = tokens.length; i < l; i++) {
				var token = tokens[i];
				var newToken = token.clone();
				newTokens.push(newToken);
				if (!Array.isArray(token.value))
				  continue;

				if (token.value.length > 1) {
				  verticalTokens.push({
					prop: token.prop,
					value: token.value[1],
					isImportant: token.isImportant
				  });
				}

				newToken.value = token.value[0];
			  }

			  var result = putTogether.takeCareOfInherit(putTogether.fourUnits)(prop, newTokens, isImportant);
			  if (verticalTokens.length > 0) {
				var verticalResult = putTogether.takeCareOfInherit(putTogether.fourUnits)(prop, verticalTokens, isImportant);
				if (result.value != verticalResult.value)
				  result.value += '/' + verticalResult.value;
			  }

			  return result;
			}
		  };

		  // Properties to process
		  // Extend this object in order to add support for more properties in the optimizer.
		  //
		  // Each key in this object represents a CSS property and should be an object.
		  // Such an object contains properties that describe how the represented CSS property should be handled.
		  // Possible options:
		  //
		  // * components: array (Only specify for shorthand properties.)
		  //   Contains the names of the granular properties this shorthand compacts.
		  //
		  // * canOverride: function (Default is canOverride.sameValue - meaning that they'll only be merged if they have the same value.)
		  //   Returns whether two tokens of this property can be merged with each other.
		  //   This property has no meaning for shorthands.
		  //
		  // * defaultValue: string
		  //   Specifies the default value of the property according to the CSS standard.
		  //   For shorthand, this is used when every component is set to its default value, therefore it should be the shortest possible default value of all the components.
		  //
		  // * shortestValue: string
		  //   Specifies the shortest possible value the property can possibly have.
		  //   (Falls back to defaultValue if unspecified.)
		  //
		  // * breakUp: function (Only specify for shorthand properties.)
		  //   Breaks the shorthand up to its components.
		  //
		  // * putTogether: function (Only specify for shorthand properties.)
		  //   Puts the shorthand together from its components.
		  //
		  var processable = {
			'color': {
			  canOverride: canOverride.color,
			  defaultValue: 'transparent',
			  shortestValue: 'red'
			},
			// background ------------------------------------------------------------------------------
			'background': {
			  components: [
				'background-image',
				'background-position',
				'background-size',
				'background-repeat',
				'background-attachment',
				'background-origin',
				'background-clip',
				'background-color'
			  ],
			  breakUp: breakUp.commaSeparatedMulitpleValues(breakUp.background),
			  putTogether: putTogether.commaSeparatedMulitpleValues(
				putTogether.takeCareOfInherit(putTogether.bySpacesOmitDefaults)
			  ),
			  defaultValue: '0 0',
			  shortestValue: '0'
			},
			'background-clip': {
			  canOverride: canOverride.always,
			  defaultValue: 'border-box',
			  shortestValue: 'border-box',
			  shorthandFollows: 'background-origin',
			  mergeWithPrevious: true
			},
			'background-color': {
			  canOverride: canOverride.color,
			  defaultValue: 'transparent',
			  multiValueLastOnly: true,
			  nonMergeableValue: 'none',
			  shortestValue: 'red'
			},
			'background-image': {
			  canOverride: canOverride.backgroundImage,
			  defaultValue: 'none'
			},
			'background-origin': {
			  canOverride: canOverride.always,
			  defaultValue: 'padding-box',
			  shortestValue: 'border-box'
			},
			'background-repeat': {
			  canOverride: canOverride.always,
			  defaultValue: 'repeat'
			},
			'background-position': {
			  canOverride: canOverride.always,
			  defaultValue: '0 0',
			  shortestValue: '0'
			},
			'background-size': {
			  canOverride: canOverride.always,
			  defaultValue: 'auto',
			  shortestValue: '0 0',
			  prefixShorthandValueWith: '/',
			  shorthandFollows: 'background-position'
			},
			'background-attachment': {
			  canOverride: canOverride.always,
			  defaultValue: 'scroll'
			},
			'border': {
			  breakUp: breakUp.border,
			  canOverride: canOverride.border,
			  components: [
				'border-width',
				'border-style',
				'border-color'
			  ],
			  defaultValue: 'none',
			  putTogether: putTogether.takeCareOfInherit(putTogether.bySpacesOmitDefaults)
			},
			'border-color': {
			  canOverride: canOverride.color,
			  defaultValue: 'none'
			},
			'border-style': {
			  canOverride: canOverride.always,
			  defaultValue: 'none'
			},
			'border-width': {
			  canOverride: canOverride.unit,
			  defaultValue: 'medium',
			  shortestValue: '0'
			},
			// list-style ------------------------------------------------------------------------------
			'list-style': {
			  components: [
				'list-style-type',
				'list-style-position',
				'list-style-image'
			  ],
			  canOverride: canOverride.always,
			  breakUp: breakUp.listStyle,
			  putTogether: putTogether.takeCareOfInherit(putTogether.bySpacesOmitDefaults),
			  defaultValue: 'outside', // can't use 'disc' because that'd override default 'decimal' for <ol>
			  shortestValue: 'none'
			},
			'list-style-type' : {
			  canOverride: canOverride.always,
			  shortestValue: 'none',
			  defaultValue: '__hack'
			  // NOTE: we can't tell the real default value here, it's 'disc' for <ul> and 'decimal' for <ol>
			  //       -- this is a hack, but it doesn't matter because this value will be either overridden or it will disappear at the final step anyway
			},
			'list-style-position' : {
			  canOverride: canOverride.always,
			  defaultValue: 'outside',
			  shortestValue: 'inside'
			},
			'list-style-image' : {
			  canOverride: canOverride.always,
			  defaultValue: 'none'
			},
			// outline ------------------------------------------------------------------------------
			'outline': {
			  components: [
				'outline-color',
				'outline-style',
				'outline-width'
			  ],
			  breakUp: breakUp.outline,
			  putTogether: putTogether.takeCareOfInherit(putTogether.bySpacesOmitDefaults),
			  defaultValue: '0'
			},
			'outline-color': {
			  canOverride: canOverride.color,
			  defaultValue: 'invert',
			  shortestValue: 'red'
			},
			'outline-style': {
			  canOverride: canOverride.always,
			  defaultValue: 'none'
			},
			'outline-width': {
			  canOverride: canOverride.unit,
			  defaultValue: 'medium',
			  shortestValue: '0'
			},
			// transform
			'-moz-transform': {
			  canOverride: canOverride.sameFunctionOrValue
			},
			'-ms-transform': {
			  canOverride: canOverride.sameFunctionOrValue
			},
			'-webkit-transform': {
			  canOverride: canOverride.sameFunctionOrValue
			},
			'transform': {
			  canOverride: canOverride.sameFunctionOrValue
			}
		  };

		  var addFourValueShorthand = function (prop, components, options) {
			options = options || {};
			processable[prop] = {
			  components: components,
			  breakUp: options.breakUp || breakUp.fourBySpaces,
			  putTogether: options.putTogether || putTogether.takeCareOfInherit(putTogether.fourUnits),
			  defaultValue: options.defaultValue || '0',
			  shortestValue: options.shortestValue
			};
			for (var i = 0; i < components.length; i++) {
			  processable[components[i]] = {
				breakUp: options.breakUp || breakUp.fourBySpaces,
				canOverride: options.canOverride || canOverride.unit,
				defaultValue: options.defaultValue || '0',
				shortestValue: options.shortestValue
			  };
			}
		  };

		  ['', '-moz-', '-o-', '-webkit-'].forEach(function (prefix) {
			addFourValueShorthand(prefix + 'border-radius', [
			  prefix + 'border-top-left-radius',
			  prefix + 'border-top-right-radius',
			  prefix + 'border-bottom-right-radius',
			  prefix + 'border-bottom-left-radius'
			], {
			  breakUp: breakUp.borderRadius,
			  putTogether: putTogether.borderRadius
			});
		  });

		  addFourValueShorthand('border-color', [
			'border-top-color',
			'border-right-color',
			'border-bottom-color',
			'border-left-color'
		  ], {
			breakUp: breakUp.fourBySpaces,
			canOverride: canOverride.color,
			defaultValue: 'currentColor',
			shortestValue: 'red'
		  });

		  addFourValueShorthand('border-style', [
			'border-top-style',
			'border-right-style',
			'border-bottom-style',
			'border-left-style'
		  ], {
			breakUp: breakUp.fourBySpaces,
			canOverride: canOverride.always,
			defaultValue: 'none'
		  });

		  addFourValueShorthand('border-width', [
			'border-top-width',
			'border-right-width',
			'border-bottom-width',
			'border-left-width'
		  ], {
			defaultValue: 'medium',
			shortestValue: '0'
		  });

		  addFourValueShorthand('padding', [
			'padding-top',
			'padding-right',
			'padding-bottom',
			'padding-left'
		  ]);

		  addFourValueShorthand('margin', [
			'margin-top',
			'margin-right',
			'margin-bottom',
			'margin-left'
		  ]);

		  // Set some stuff iteratively
		  for (var proc in processable) {
			if (!processable.hasOwnProperty(proc))
			  continue;

			var currDesc = processable[proc];

			if (!(currDesc.components instanceof Array) || currDesc.components.length === 0)
			  continue;

			currDesc.isShorthand = true;

			for (var cI = 0; cI < currDesc.components.length; cI++) {
			  if (!processable[currDesc.components[cI]]) {
				throw new Error('"' + currDesc.components[cI] + '" is defined as a component of "' + proc + '" but isn\'t defined in processable.');
			  }
			  processable[currDesc.components[cI]].componentOf = proc;
			}
		  }

		  var Token = tokenModule.createTokenPrototype(processable);

		  return {
			implementedFor: /background|border|color|list|margin|outline|padding|transform/,
			processable: function (compatibility) {
			  // FIXME: we need a proper OO way
			  validator.setCompatibility(compatibility);

			  return processable;
			},
			Token: Token
		  };
		})();

		return exports;
	};
	//#endregion

	//#region URL: /properties/override-compactor
	modules['/properties/override-compactor'] = function () {
		// Compacts the given tokens according to their ability to override each other.

		var validator = require('/properties/validator');

		var exports = (function () {
		  // Default override function: only allow overrides when the two values are the same
		  var sameValue = function (val1, val2) {
			return val1 === val2;
		  };

		  var compactOverrides = function (tokens, processable, Token, compatibility) {
			var result, can, token, t, i, ii, iiii, oldResult, matchingComponent;

			// Used when searching for a component that matches token
			var nameMatchFilter1 = function (x) {
			  return x.prop === token.prop;
			};
			// Used when searching for a component that matches t
			var nameMatchFilter2 = function (x) {
			  return x.prop === t.prop;
			};

			function willResultInShorterValue (shorthand, token) {
			  var shorthandCopy = shorthand.clone();
			  shorthandCopy.isDirty = true;
			  shorthandCopy.isShorthand = true;
			  shorthandCopy.components = [];

			  shorthand.components.forEach(function (component) {
				var componentCopy = component.clone();
				if (component.prop == token.prop)
				  componentCopy.value = token.value;

				shorthandCopy.components.push(componentCopy);
			  });

			  return Token.getDetokenizedLength([shorthand, token]) >= Token.getDetokenizedLength([shorthandCopy]);
			}

			// Go from the end and always take what the current token can't override as the new result set
			// NOTE: can't cache result.length here because it will change with every iteration
			for (result = tokens, i = 0; (ii = result.length - 1 - i) >= 0; i++) {
			  token = result[ii];
			  can = (processable[token.prop] && processable[token.prop].canOverride) || sameValue;
			  oldResult = result;
			  result = [];

			  // Special flag which indicates that the current token should be removed
			  var removeSelf = false;
			  var oldResultLength = oldResult.length;

			  for (var iii = 0; iii < oldResultLength; iii++) {
				t = oldResult[iii];

				// A token can't override itself (checked by reference, not by value)
				// NOTE: except when we explicitly tell it to remove itself
				if (t === token && !removeSelf) {
				  result.push(t);
				  continue;
				}

				// Only an important token can even try to override tokens that come after it
				if (iii > ii && !token.isImportant) {
				  result.push(t);
				  continue;
				}

				// If an important component tries to override an important shorthand and it is not yet merged
				// just make sure it is not lost
				if (iii > ii && t.isImportant && token.isImportant && t.prop != token.prop && t.isComponentOf(token)) {
				  result.push(t);
				  continue;
				}

				// A nonimportant token can never override an important one
				if (t.isImportant && !token.isImportant) {
				  result.push(t);
				  continue;
				}

				if (token.isShorthand && !t.isShorthand && t.isComponentOf(token)) {
				  // token (a shorthand) is trying to override t (a component)

				  // Find the matching component in the shorthand
				  matchingComponent = token.components.filter(nameMatchFilter2)[0];
				  can = (processable[t.prop] && processable[t.prop].canOverride) || sameValue;
				  if (!can(t.value, matchingComponent.value)) {
					// The shorthand can't override the component
					result.push(t);
				  }
				} else if (t.isShorthand && !token.isShorthand && token.isComponentOf(t)) {
				  // token (a component) is trying to override a component of t (a shorthand)

				  // Find the matching component in the shorthand
				  matchingComponent = t.components.filter(nameMatchFilter1)[0];
				  if (can(matchingComponent.value, token.value)) {
					// The component can override the matching component in the shorthand
					var disabledForToken = !compatibility.properties.backgroundSizeMerging && token.prop.indexOf('background-size') > -1 ||
					  processable[token.prop].nonMergeableValue && processable[token.prop].nonMergeableValue == token.value;

					if (disabledForToken) {
					  result.push(t);
					  continue;
					}

					if (!compatibility.properties.merging) {
					  // in compatibility mode check if shorthand in not less understandable than merged-in value
					  var wouldBreakCompatibility = false;
					  for (iiii = 0; iiii < t.components.length; iiii++) {
						var o = processable[t.components[iiii].prop];
						can = (o && o.canOverride) || sameValue;

						if (!can(o.defaultValue, t.components[iiii].value)) {
						  wouldBreakCompatibility = true;
						  break;
						}
					  }

					  if (wouldBreakCompatibility) {
						result.push(t);
						continue;
					  }
					}

					if ((!token.isImportant || token.isImportant && matchingComponent.isImportant) && willResultInShorterValue(t, token)) {
					  // The overriding component is non-important which means we can simply include it into the shorthand
					  // NOTE: stuff that can't really be included, like inherit, is taken care of at the final step, not here
					  matchingComponent.value = token.value;
					  // We use the special flag to get rid of the component
					  removeSelf = true;
					} else {
					  // The overriding component is important; sadly we can't get rid of it,
					  // but we can still mark the matching component in the shorthand as irrelevant
					  matchingComponent.isIrrelevant = true;
					}
					t.isDirty = true;
				  }
				  result.push(t);
				} else if (token.isShorthand && t.isShorthand && token.prop === t.prop) {
				  // token is a shorthand and is trying to override another instance of the same shorthand

				  // Can only override other shorthand when each of its components can override each of the other's components
				  for (iiii = 0; iiii < t.components.length; iiii++) {
					can = (processable[t.components[iiii].prop] && processable[t.components[iiii].prop].canOverride) || sameValue;
					if (!can(t.components[iiii].value, token.components[iiii].value)) {
					  result.push(t);
					  break;
					}
					if (t.components[iiii].isImportant && token.components[iiii].isImportant && (validator.isValidFunction(t.components[iiii].value) ^ validator.isValidFunction(token.components[iiii].value))) {
					  result.push(t);
					  break;
					}
				  }
				} else if (t.prop !== token.prop || !can(t.value, token.value)) {
				  // in every other case, use the override mechanism
				  result.push(t);
				} else if (t.isImportant && token.isImportant && (validator.isValidFunction(t.value) ^ validator.isValidFunction(token.value))) {
				  result.push(t);
				}
			  }
			  if (removeSelf) {
				i--;
			  }
			}

			return result;
		  };

		  return {
			compactOverrides: compactOverrides
		  };

		})();

		return exports;
	};
	//#endregion
	
	//#region URL: /properties/shorthand-compactor
	modules['/properties/shorthand-compactor'] = function () {
		// Compacts the tokens by transforming properties into their shorthand notations when possible

		var exports = (function () {
		  var isHackValue = function (t) { return t.value === '__hack'; };

		  var compactShorthands = function(tokens, isImportant, processable, Token) {
			// Contains the components found so far, grouped by shorthand name
			var componentsSoFar = { };

			// Initializes a prop in componentsSoFar
			var initSoFar = function (shprop, last, clearAll) {
			  var found = {};
			  var shorthandPosition;

			  if (!clearAll && componentsSoFar[shprop]) {
				for (var i = 0; i < processable[shprop].components.length; i++) {
				  var prop = processable[shprop].components[i];
				  found[prop] = [];

				  if (!(componentsSoFar[shprop].found[prop]))
					continue;

				  for (var ii = 0; ii < componentsSoFar[shprop].found[prop].length; ii++) {
					var comp = componentsSoFar[shprop].found[prop][ii];

					if (comp.isMarkedForDeletion)
					  continue;

					found[prop].push(comp);

					if (comp.position && (!shorthandPosition || comp.position < shorthandPosition))
					  shorthandPosition = comp.position;
				  }
				}
			  }
			  componentsSoFar[shprop] = {
				lastShorthand: last,
				found: found,
				shorthandPosition: shorthandPosition
			  };
			};

			// Adds a component to componentsSoFar
			var addComponentSoFar = function (token, index) {
			  var shprop = processable[token.prop].componentOf;
			  if (!componentsSoFar[shprop])
				initSoFar(shprop);
			  if (!componentsSoFar[shprop].found[token.prop])
				componentsSoFar[shprop].found[token.prop] = [];

			  // Add the newfound component to componentsSoFar
			  componentsSoFar[shprop].found[token.prop].push(token);

			  if (!componentsSoFar[shprop].shorthandPosition && index) {
				// If the haven't decided on where the shorthand should go, put it in the place of this component
				componentsSoFar[shprop].shorthandPosition = index;
			  }
			};

			// Tries to compact a prop in componentsSoFar
			var compactSoFar = function (prop) {
			  var i;
			  var componentsCount = processable[prop].components.length;

			  // Check basics
			  if (!componentsSoFar[prop] || !componentsSoFar[prop].found)
				return false;

			  // Find components for the shorthand
			  var components = [];
			  var realComponents = [];
			  for (i = 0 ; i < componentsCount; i++) {
				// Get property name
				var pp = processable[prop].components[i];

				if (componentsSoFar[prop].found[pp] && componentsSoFar[prop].found[pp].length) {
				  // We really found it
				  var foundRealComp = componentsSoFar[prop].found[pp][0];
				  components.push(foundRealComp);
				  if (foundRealComp.isReal !== false) {
					realComponents.push(foundRealComp);
				  }
				} else if (componentsSoFar[prop].lastShorthand) {
				  // It's defined in the previous shorthand
				  var c = componentsSoFar[prop].lastShorthand.components[i].clone(isImportant);
				  components.push(c);
				} else {
				  // Couldn't find this component at all
				  return false;
				}
			  }

			  if (realComponents.length === 0) {
				// Couldn't find enough components, sorry
				return false;
			  }

			  if (realComponents.length === componentsCount) {
				// When all the components are from real values, only allow shorthanding if their understandability allows it
				// This is the case when every component can override their default values, or when all of them use the same function

				var canOverrideDefault = true;
				var functionNameMatches = true;
				var functionName;

				for (var ci = 0; ci < realComponents.length; ci++) {
				  var rc = realComponents[ci];

				  if (!processable[rc.prop].canOverride(processable[rc.prop].defaultValue, rc.value)) {
					canOverrideDefault = false;
				  }
				  var iop = rc.value.indexOf('(');
				  if (iop >= 0) {
					var otherFunctionName = rc.value.substring(0, iop);
					if (functionName)
					  functionNameMatches = functionNameMatches && otherFunctionName === functionName;
					else
					  functionName = otherFunctionName;
				  }
				}

				if (!canOverrideDefault || !functionNameMatches)
				  return false;
			  }

			  // Compact the components into a shorthand
			  var compacted = processable[prop].putTogether(prop, components, isImportant);
			  if (!(compacted instanceof Array)) {
				compacted = [compacted];
			  }

			  var compactedLength = Token.getDetokenizedLength(compacted);
			  var authenticLength = Token.getDetokenizedLength(realComponents);

			  if (realComponents.length === componentsCount || compactedLength < authenticLength || components.some(isHackValue)) {
				compacted[0].isShorthand = true;
				compacted[0].components = processable[prop].breakUp(compacted[0]);

				// Mark the granular components for deletion
				for (i = 0; i < realComponents.length; i++) {
				  realComponents[i].isMarkedForDeletion = true;
				}

				// Mark the position of the new shorthand
				tokens[componentsSoFar[prop].shorthandPosition].replaceWith = compacted;

				// Reinitialize the thing for further compacting
				initSoFar(prop, compacted[0]);
				for (i = 1; i < compacted.length; i++) {
				  addComponentSoFar(compacted[i]);
				}

				// Yes, we can keep the new shorthand!
				return true;
			  }

			  return false;
			};

			// Tries to compact all properties currently in componentsSoFar
			var compactAllSoFar = function () {
			  for (var i in componentsSoFar) {
				if (componentsSoFar.hasOwnProperty(i)) {
				  while (compactSoFar(i)) { }
				}
			  }
			};

			var i, token;

			// Go through each token and collect components for each shorthand as we go on
			for (i = 0; i < tokens.length; i++) {
			  token = tokens[i];
			  if (token.isMarkedForDeletion) {
				continue;
			  }
			  if (!processable[token.prop]) {
				// We don't know what it is, move on
				continue;
			  }
			  if (processable[token.prop].isShorthand) {
				// Found an instance of a full shorthand
				// NOTE: we should NOT mix together tokens that come before and after the shorthands

				if (token.isImportant === isImportant || (token.isImportant && !isImportant)) {
				  // Try to compact what we've found so far
				  while (compactSoFar(token.prop)) { }
				  // Reset
				  initSoFar(token.prop, token, true);
				}

				// TODO: when the old optimizer is removed, take care of this corner case:
				//   div{background-color:#111;background-image:url(aaa);background:linear-gradient(aaa);background-repeat:no-repeat;background-position:1px 2px;background-attachment:scroll}
				//   -> should not be shorthanded / minified at all because the result wouldn't be equivalent to the original in any browser
			  } else if (processable[token.prop].componentOf) {
				// Found a component of a shorthand
				if (token.isImportant === isImportant) {
				  // Same importantness
				  token.position = i;
				  addComponentSoFar(token, i);
				} else if (!isImportant && token.isImportant) {
				  // Use importants for optimalization opportunities
				  // https://github.com/jakubpawlowicz/clean-css/issues/184
				  var importantTrickComp = new Token(token.prop, token.value, isImportant);
				  importantTrickComp.isIrrelevant = true;
				  importantTrickComp.isReal = false;
				  addComponentSoFar(importantTrickComp);
				}
			  } else {
				// This is not a shorthand and not a component, don't care about it
				continue;
			  }
			}

			// Perform all possible compactions
			compactAllSoFar();

			// Process the results - throw away stuff marked for deletion, insert compacted things, etc.
			var result = [];
			for (i = 0; i < tokens.length; i++) {
			  token = tokens[i];

			  if (token.replaceWith) {
				for (var ii = 0; ii < token.replaceWith.length; ii++) {
				  result.push(token.replaceWith[ii]);
				}
			  }
			  if (!token.isMarkedForDeletion) {
				result.push(token);
			  }

			  token.isMarkedForDeletion = false;
			  token.replaceWith = null;
			}

			return result;
		  };

		  return {
			compactShorthands: compactShorthands
		  };

		})();

		return exports;
	};
	//#endregion
	
	//#region URL: /properties/optimizer
	modules['/properties/optimizer'] = function () {
		var processableInfo = require('/properties/processable');
		var overrideCompactor = require('/properties/override-compactor');
		var shorthandCompactor = require('/properties/shorthand-compactor');

		function valueMapper(object) { return object.value; }

		var exports = function Optimizer(options, context) {
		  var overridable = {
			'animation-delay': ['animation'],
			'animation-direction': ['animation'],
			'animation-duration': ['animation'],
			'animation-fill-mode': ['animation'],
			'animation-iteration-count': ['animation'],
			'animation-name': ['animation'],
			'animation-play-state': ['animation'],
			'animation-timing-function': ['animation'],
			'-moz-animation-delay': ['-moz-animation'],
			'-moz-animation-direction': ['-moz-animation'],
			'-moz-animation-duration': ['-moz-animation'],
			'-moz-animation-fill-mode': ['-moz-animation'],
			'-moz-animation-iteration-count': ['-moz-animation'],
			'-moz-animation-name': ['-moz-animation'],
			'-moz-animation-play-state': ['-moz-animation'],
			'-moz-animation-timing-function': ['-moz-animation'],
			'-o-animation-delay': ['-o-animation'],
			'-o-animation-direction': ['-o-animation'],
			'-o-animation-duration': ['-o-animation'],
			'-o-animation-fill-mode': ['-o-animation'],
			'-o-animation-iteration-count': ['-o-animation'],
			'-o-animation-name': ['-o-animation'],
			'-o-animation-play-state': ['-o-animation'],
			'-o-animation-timing-function': ['-o-animation'],
			'-webkit-animation-delay': ['-webkit-animation'],
			'-webkit-animation-direction': ['-webkit-animation'],
			'-webkit-animation-duration': ['-webkit-animation'],
			'-webkit-animation-fill-mode': ['-webkit-animation'],
			'-webkit-animation-iteration-count': ['-webkit-animation'],
			'-webkit-animation-name': ['-webkit-animation'],
			'-webkit-animation-play-state': ['-webkit-animation'],
			'-webkit-animation-timing-function': ['-webkit-animation'],
			'background-clip': ['background'],
			'background-origin': ['background'],
			'border-color': ['border'],
			'border-style': ['border'],
			'border-width': ['border'],
			'border-bottom': ['border'],
			'border-bottom-color': ['border-bottom', 'border-color', 'border'],
			'border-bottom-style': ['border-bottom', 'border-style', 'border'],
			'border-bottom-width': ['border-bottom', 'border-width', 'border'],
			'border-left': ['border'],
			'border-left-color': ['border-left', 'border-color', 'border'],
			'border-left-style': ['border-left', 'border-style', 'border'],
			'border-left-width': ['border-left', 'border-width', 'border'],
			'border-right': ['border'],
			'border-right-color': ['border-right', 'border-color', 'border'],
			'border-right-style': ['border-right', 'border-style', 'border'],
			'border-right-width': ['border-right', 'border-width', 'border'],
			'border-top': ['border'],
			'border-top-color': ['border-top', 'border-color', 'border'],
			'border-top-style': ['border-top', 'border-style', 'border'],
			'border-top-width': ['border-top', 'border-width', 'border'],
			'font-family': ['font'],
			'font-size': ['font'],
			'font-style': ['font'],
			'font-variant': ['font'],
			'font-weight': ['font'],
			'margin-bottom': ['margin'],
			'margin-left': ['margin'],
			'margin-right': ['margin'],
			'margin-top': ['margin'],
			'padding-bottom': ['padding'],
			'padding-left': ['padding'],
			'padding-right': ['padding'],
			'padding-top': ['padding'],
			'transition-delay': ['transition'],
			'transition-duration': ['transition'],
			'transition-property': ['transition'],
			'transition-timing-function': ['transition'],
			'-moz-transition-delay': ['-moz-transition'],
			'-moz-transition-duration': ['-moz-transition'],
			'-moz-transition-property': ['-moz-transition'],
			'-moz-transition-timing-function': ['-moz-transition'],
			'-o-transition-delay': ['-o-transition'],
			'-o-transition-duration': ['-o-transition'],
			'-o-transition-property': ['-o-transition'],
			'-o-transition-timing-function': ['-o-transition'],
			'-webkit-transition-delay': ['-webkit-transition'],
			'-webkit-transition-duration': ['-webkit-transition'],
			'-webkit-transition-property': ['-webkit-transition'],
			'-webkit-transition-timing-function': ['-webkit-transition']
		  };

		  var compatibility = options.compatibility;
		  var aggressiveMerging = options.aggressiveMerging;
		  var shorthandCompacting = options.shorthandCompacting;

		  var IE_BACKSLASH_HACK = '\\9';
		  var processable = processableInfo.processable(compatibility);

		  var overrides = {};
		  for (var granular in overridable) {
			for (var i = 0; i < overridable[granular].length; i++) {
			  var coarse = overridable[granular][i];
			  var list = overrides[coarse];

			  if (list)
				list.push(granular);
			  else
				overrides[coarse] = [granular];
			}
		  }

		  var tokenize = function(body, selector) {
			var keyValues = [];

			for (var i = 0, l = body.length; i < l; i++) {
			  var token = body[i];
			  var firstColon = token.value.indexOf(':');
			  var property = token.value.substring(0, firstColon);
			  var value = token.value.substring(firstColon + 1);
			  if (value === '') {
				context.warnings.push('Empty property \'' + property + '\' inside \'' + selector.map(valueMapper).join(',') + '\' selector. Ignoring.');
				continue;
			  }

			  keyValues.push([
				property,
				value,
				token.value.indexOf('!important') > -1,
				token.value.indexOf(IE_BACKSLASH_HACK, firstColon + 1) === token.value.length - IE_BACKSLASH_HACK.length,
				token.metadata
			  ]);
			}

			return keyValues;
		  };

		  var optimize = function(tokens, allowAdjacent) {
			var merged = [];
			var properties = [];
			var lastProperty = null;
			var rescanTrigger = {};

			var removeOverridenBy = function(property, isImportant) {
			  var overrided = overrides[property];
			  for (var i = 0, l = overrided.length; i < l; i++) {
				for (var j = 0; j < properties.length; j++) {
				  if (properties[j] != overrided[i] || (merged[j][2] && !isImportant))
					continue;

				  merged.splice(j, 1);
				  properties.splice(j, 1);
				  j -= 1;
				}
			  }
			};

			var mergeablePosition = function(position) {
			  if (allowAdjacent === false || allowAdjacent === true)
				return allowAdjacent;

			  return allowAdjacent.indexOf(position) > -1;
			};

			tokensLoop:
			for (var i = 0, l = tokens.length; i < l; i++) {
			  var token = tokens[i];
			  var property = token[0];
			  var value = token[1];
			  var isImportant = token[2];
			  var isIEHack = token[3];
			  var _property = (property == '-ms-filter' || property == 'filter') ?
				(lastProperty == 'background' || lastProperty == 'background-image' ? lastProperty : property) :
				property;
			  var toOverridePosition = 0;

			  if (isIEHack && !compatibility.properties.ieSuffixHack)
				continue;

			  // comment is necessary - we assume that if two properties are one after another
			  // then it is intentional way of redefining property which may not be widely supported
			  // e.g. a{display:inline-block;display:-moz-inline-box}
			  // however if `mergeablePosition` yields true then the rule does not apply
			  // (e.g merging two adjacent selectors: `a{display:block}a{display:block}`)
			  if (aggressiveMerging && property !== '' && _property != lastProperty || mergeablePosition(i)) {
				while (true) {
				  toOverridePosition = properties.indexOf(_property, toOverridePosition);
				  if (toOverridePosition == -1)
					break;

				  var lastToken = merged[toOverridePosition];
				  var wasImportant = lastToken[2];
				  var wasIEHack = lastToken[3];

				  if (wasImportant && !isImportant)
					continue tokensLoop;

				  if (compatibility.properties.ieSuffixHack && !wasIEHack && isIEHack)
					break;

				  var _info = processable[_property];
				  if (!isIEHack && !wasIEHack && _info && _info.canOverride && !_info.canOverride(tokens[toOverridePosition][1], value))
					break;

				  merged.splice(toOverridePosition, 1);
				  properties.splice(toOverridePosition, 1);
				}
			  }

			  merged.push(token);
			  properties.push(_property);

			  // certain properties (see values of `overridable`) should trigger removal of
			  // more granular properties (see keys of `overridable`)
			  if (rescanTrigger[_property])
				removeOverridenBy(_property, isImportant);

			  // add rescan triggers - if certain property appears later in the list a rescan needs
			  // to be triggered, e.g 'border-top' triggers a rescan after 'border-top-width' and
			  // 'border-top-color' as they can be removed
			  for (var j = 0, list = overridable[_property] || [], m = list.length; j < m; j++)
				rescanTrigger[list[j]] = true;

			  lastProperty = _property;
			}

			return merged;
		  };

		  var rebuild = function(tokens) {
			var tokenized = [];
			var list = [];
			var eligibleForCompacting = false;

			for (var i = 0, l = tokens.length; i < l; i++) {
			  if (!eligibleForCompacting && processableInfo.implementedFor.test(tokens[i][0]))
				eligibleForCompacting = true;

			  // FIXME: the check should be gone with #396
			  var property = !tokens[i][0] && tokens[i][1].indexOf('__ESCAPED_') === 0 ?
				tokens[i][1] :
				tokens[i][0] + ':' + tokens[i][1];
			  tokenized.push({ value: property, metadata: tokens[i][4] });
			  list.push(property);
			}

			return {
			  compactFurther: eligibleForCompacting,
			  list: list,
			  tokenized: tokenized
			};
		  };

		  var compact = function (input) {
			var Token = processableInfo.Token;

			var tokens = Token.tokenize(input);

			tokens = overrideCompactor.compactOverrides(tokens, processable, Token, compatibility);
			tokens = shorthandCompactor.compactShorthands(tokens, false, processable, Token);
			tokens = shorthandCompactor.compactShorthands(tokens, true, processable, Token);

			return Token.detokenize(tokens);
		  };

		  return {
			process: function(selector, body, allowAdjacent, compactProperties) {
			  var tokenized = tokenize(body, selector);
			  var optimized = optimize(tokenized, allowAdjacent);
			  var rebuilt = rebuild(optimized);

			  return shorthandCompacting && compactProperties && rebuilt.compactFurther ?
				compact(rebuilt.tokenized) :
				rebuilt;
			}
		  };
		};

		return exports;
	};
	//#endregion
	
	//#region URL: /properties/extractor
	modules['/properties/extractor'] = function () {
		// This extractor is used in advanced optimizations
		// IMPORTANT: Mind Token class and this code is not related!
		// Properties will be tokenized in one step, see #429

		function extract(token) {
		  var properties = [];

		  if (token.kind == 'selector') {
			var inSimpleSelector = !/[\.\+#>~\s]/.test(token.metadata.selector);
			for (var i = 0, l = token.metadata.bodiesList.length; i < l; i++) {
			  var property = token.metadata.bodiesList[i];
			  if (property.indexOf('__ESCAPED') === 0)
				continue;

			  var splitAt = property.indexOf(':');
			  var name = property.substring(0, splitAt);
			  if (!name)
				continue;

			  var nameRoot = findNameRoot(name);

			  properties.push([
				name,
				property.substring(splitAt + 1),
				nameRoot,
				property,
				token.metadata.selectorsList,
				inSimpleSelector
			  ]);
			}
		  } else if (token.kind == 'block') {
			for (var j = 0, k = token.body.length; j < k; j++) {
			  properties = properties.concat(extract(token.body[j]));
			}
		  }

		  return properties;
		}

		function findNameRoot(name) {
		  if (name == 'list-style')
			return name;
		  if (name.indexOf('-radius') > 0)
			return 'border-radius';
		  if (name.indexOf('border-') === 0)
			return name.match(/border\-\w+/)[0];
		  if (name.indexOf('text-') === 0)
			return name;

		  return name.replace(/^\-\w+\-/, '').match(/([a-zA-Z]+)/)[0].toLowerCase();
		}

		return extract;
	};
	//#endregion
	
	//#region URL: /properties/reorderable
	modules['/properties/reorderable'] = function () {
		var FLEX_PROPERTIES = /align\-items|box\-align|box\-pack|flex|justify/;

		function canReorder(left, right) {
		  for (var i = right.length - 1; i >= 0; i--) {
			for (var j = left.length - 1; j >= 0; j--) {
			  if (!canReorderSingle(left[j], right[i]))
				return false;
			}
		  }

		  return true;
		}

		function canReorderSingle(left, right) {
		  var leftName = left[0];
		  var leftValue = left[1];
		  var leftNameRoot = left[2];
		  var leftSelector = left[4];
		  var leftInSimpleSelector = left[5];
		  var rightName = right[0];
		  var rightValue = right[1];
		  var rightNameRoot = right[2];
		  var rightSelector = right[4];
		  var rightInSimpleSelector = right[5];

		  if (leftName == 'font' && rightName == 'line-height' || rightName == 'font' && leftName == 'line-height')
			return false;
		  if (FLEX_PROPERTIES.test(leftName) && FLEX_PROPERTIES.test(rightName))
			return false;
		  if (leftNameRoot != rightNameRoot)
			return true;
		  if (leftName == rightName && leftNameRoot == rightNameRoot && leftValue == rightValue)
			return true;
		  if (leftName != rightName && leftNameRoot == rightNameRoot && leftName != leftNameRoot && rightName != rightNameRoot)
			return true;
		  if (leftName != rightName && leftNameRoot == rightNameRoot && leftValue == rightValue)
			return true;
		  if (rightInSimpleSelector && leftInSimpleSelector && selectorsDoNotOverlap(rightSelector, leftSelector))
			return true;

		  return false;
		}

		function selectorsDoNotOverlap(s1, s2) {
		  for (var i = 0, l = s1.length; i < l; i++) {
			if (s2.indexOf(s1[i]) > -1)
			  return false;
		  }

		  return true;
		}

		var exports = {
		  canReorder: canReorder,
		  canReorderSingle: canReorderSingle
		};

		return exports;
	};
	//#endregion
	
	//#region URL: /selectors/optimizers/advanced
	modules['/selectors/optimizers/advanced'] = function () {
		var PropertyOptimizer = require('/properties/optimizer');
		var CleanUp = require('/selectors/optimizers/clean-up');

		var extractProperties = require('/properties/extractor');
		var canReorder = require('/properties/reorderable').canReorder;
		var canReorderSingle = require('/properties/reorderable').canReorderSingle;

		function AdvancedOptimizer(options, context) {
		  this.options = options;
		  this.minificationsMade = [];
		  this.propertyOptimizer = new PropertyOptimizer(this.options, context);
		}

		function changeBodyOf(token, newBody) {
		  token.body = newBody.tokenized;
		  token.metadata.body = newBody.list.join(';');
		  token.metadata.bodiesList = newBody.list;
		}

		function changeSelectorOf(token, newSelectors) {
		  token.value = newSelectors.tokenized;
		  token.metadata.selector = newSelectors.list.join(',');
		  token.metadata.selectorsList = newSelectors.list;
		}

		function unsafeSelector(value) {
		  return /\.|\*| :/.test(value);
		}

		function naturalSorter(a, b) {
		  return a > b;
		}

		AdvancedOptimizer.prototype.isSpecial = function (selector) {
		  return this.options.compatibility.selectors.special.test(selector);
		};

		AdvancedOptimizer.prototype.removeDuplicates = function (tokens) {
		  var matched = {};
		  var forRemoval = [];

		  for (var i = 0, l = tokens.length; i < l; i++) {
			var token = tokens[i];
			if (token.kind != 'selector')
			  continue;

			var id = token.metadata.body + '@' + token.metadata.selector;
			var alreadyMatched = matched[id];

			if (alreadyMatched) {
			  forRemoval.push(alreadyMatched[0]);
			  alreadyMatched.unshift(i);
			} else {
			  matched[id] = [i];
			}
		  }

		  forRemoval = forRemoval.sort(function(a, b) {
			return a > b ? 1 : -1;
		  });

		  for (var j = 0, n = forRemoval.length; j < n; j++) {
			tokens.splice(forRemoval[j] - j, 1);
		  }

		  this.minificationsMade.unshift(forRemoval.length > 0);
		};

		AdvancedOptimizer.prototype.mergeAdjacent = function (tokens) {
		  var forRemoval = [];
		  var lastToken = { selector: null, body: null };
		  var adjacentSpace = this.options.compatibility.selectors.adjacentSpace;

		  for (var i = 0, l = tokens.length; i < l; i++) {
			var token = tokens[i];

			if (token.kind != 'selector') {
			  lastToken = { selector: null, body: null };
			  continue;
			}

			if (lastToken.kind == 'selector' && token.metadata.selector == lastToken.metadata.selector) {
			  var joinAt = [lastToken.body.length];
			  changeBodyOf(
				lastToken,
				this.propertyOptimizer.process(token.value, lastToken.body.concat(token.body), joinAt, true)
			  );
			  forRemoval.push(i);
			} else if (lastToken.body && token.metadata.body == lastToken.metadata.body &&
				!this.isSpecial(token.metadata.selector) && !this.isSpecial(lastToken.metadata.selector)) {
			  changeSelectorOf(
				lastToken,
				CleanUp.selectors(lastToken.value.concat(token.value), false, adjacentSpace)
			  );
			  forRemoval.push(i);
			} else {
			  lastToken = token;
			}
		  }

		  for (var j = 0, m = forRemoval.length; j < m; j++) {
			tokens.splice(forRemoval[j] - j, 1);
		  }

		  this.minificationsMade.unshift(forRemoval.length > 0);
		};

		AdvancedOptimizer.prototype.reduceNonAdjacent = function (tokens) {
		  var candidates = {};
		  var repeated = [];

		  for (var i = tokens.length - 1; i >= 0; i--) {
			var token = tokens[i];

			if (token.kind != 'selector')
			  continue;

			var isComplexAndNotSpecial = token.value.length > 1 && !this.isSpecial(token.metadata.selector);
			var selectors = isComplexAndNotSpecial ?
			  [token.metadata.selector].concat(token.metadata.selectorsList) :
			  [token.metadata.selector];

			for (var j = 0, m = selectors.length; j < m; j++) {
			  var selector = selectors[j];

			  if (!candidates[selector])
				candidates[selector] = [];
			  else
				repeated.push(selector);

			  candidates[selector].push({
				where: i,
				list: token.metadata.selectorsList,
				isPartial: isComplexAndNotSpecial && j > 0,
				isComplex: isComplexAndNotSpecial && j === 0
			  });
			}
		  }

		  var reducedInSimple = this.reduceSimpleNonAdjacentCases(tokens, repeated, candidates);
		  var reducedInComplex = this.reduceComplexNonAdjacentCases(tokens, candidates);

		  this.minificationsMade.unshift(reducedInSimple || reducedInComplex);
		};

		AdvancedOptimizer.prototype.reduceSimpleNonAdjacentCases = function (tokens, repeated, candidates) {
		  var reduced = false;

		  function filterOut(idx, bodies) {
			return data[idx].isPartial && bodies.length === 0;
		  }

		  function reduceBody(token, newBody, processedCount, tokenIdx) {
			if (!data[processedCount - tokenIdx - 1].isPartial) {
			  changeBodyOf(token, newBody);
			  reduced = true;
			}
		  }

		  for (var i = 0, l = repeated.length; i < l; i++) {
			var selector = repeated[i];
			var data = candidates[selector];

			this.reduceSelector(tokens, selector, data, {
			  filterOut: filterOut,
			  callback: reduceBody
			});
		  }

		  return reduced;
		};

		AdvancedOptimizer.prototype.reduceComplexNonAdjacentCases = function (tokens, candidates) {
		  var reduced = false;
		  var localContext = {};

		  function filterOut(idx) {
			return localContext.data[idx].where < localContext.intoPosition;
		  }

		  function collectReducedBodies(token, newBody, processedCount, tokenIdx) {
			if (tokenIdx === 0)
			  localContext.reducedBodies.push(newBody);
		  }

		  allSelectors:
		  for (var complexSelector in candidates) {
			var into = candidates[complexSelector];
			if (!into[0].isComplex)
			  continue;

			var intoPosition = into[into.length - 1].where;
			var intoToken = tokens[intoPosition];
			var reducedBodies = [];

			var selectors = this.isSpecial(complexSelector) ?
			  [complexSelector] :
			  into[0].list;

			localContext.intoPosition = intoPosition;
			localContext.reducedBodies = reducedBodies;

			for (var j = 0, m = selectors.length; j < m; j++) {
			  var selector = selectors[j];
			  var data = candidates[selector];

			  if (data.length < 2)
				continue allSelectors;

			  localContext.data = data;

			  this.reduceSelector(tokens, selector, data, {
				filterOut: filterOut,
				callback: collectReducedBodies
			  });

			  if (reducedBodies[reducedBodies.length - 1].list.join(';') != reducedBodies[0].list.join(';'))
				continue allSelectors;
			}

			intoToken.body = reducedBodies[0].tokenized;
			reduced = true;
		  }

		  return reduced;
		};

		AdvancedOptimizer.prototype.reduceSelector = function (tokens, selector, data, options) {
		  var bodies = [];
		  var bodiesAsList = [];
		  var joinsAt = [];
		  var processedTokens = [];

		  for (var j = data.length - 1, m = 0; j >= 0; j--) {
			if (options.filterOut(j, bodies))
			  continue;

			var where = data[j].where;
			var token = tokens[where];

			bodies = bodies.concat(token.body);
			bodiesAsList.push(token.metadata.bodiesList);
			processedTokens.push(where);
		  }

		  for (j = 0, m = bodiesAsList.length; j < m; j++) {
			if (bodiesAsList[j].length > 0)
			  joinsAt.push((joinsAt[j - 1] || 0) + bodiesAsList[j].length);
		  }

		  var optimizedBody = this.propertyOptimizer.process(selector, bodies, joinsAt, false);

		  var processedCount = processedTokens.length;
		  var propertyIdx = optimizedBody.tokenized.length - 1;
		  var tokenIdx = processedCount - 1;

		  while (tokenIdx >= 0) {
			 if ((tokenIdx === 0 || (optimizedBody.tokenized[propertyIdx] && bodiesAsList[tokenIdx].indexOf(optimizedBody.tokenized[propertyIdx].value) > -1)) && propertyIdx > -1) {
			  propertyIdx--;
			  continue;
			}

			var newBody = {
			  list: optimizedBody.list.splice(propertyIdx + 1),
			  tokenized: optimizedBody.tokenized.splice(propertyIdx + 1)
			};
			options.callback(tokens[processedTokens[tokenIdx]], newBody, processedCount, tokenIdx);

			tokenIdx--;
		  }
		};

		AdvancedOptimizer.prototype.mergeNonAdjacentBySelector = function (tokens) {
		  var allSelectors = {};
		  var repeatedSelectors = [];
		  var i;

		  for (i = tokens.length - 1; i >= 0; i--) {
			if (tokens[i].kind != 'selector')
			  continue;
			if (tokens[i].body.length === 0)
			  continue;

			var selector = tokens[i].metadata.selector;
			allSelectors[selector] = [i].concat(allSelectors[selector] || []);

			if (allSelectors[selector].length == 2)
			  repeatedSelectors.push(selector);
		  }

		  for (i = repeatedSelectors.length - 1; i >= 0; i--) {
			var positions = allSelectors[repeatedSelectors[i]];

			selectorIterator:
			for (var j = positions.length - 1; j > 0; j--) {
			  var positionOne = positions[j - 1];
			  var tokenOne = tokens[positionOne];
			  var positionTwo = positions[j];
			  var tokenTwo = tokens[positionTwo];

			  directionIterator:
			  for (var direction = 1; direction >= -1; direction -= 2) {
				var topToBottom = direction == 1;
				var from = topToBottom ? positionOne + 1 : positionTwo - 1;
				var to = topToBottom ? positionTwo : positionOne;
				var delta = topToBottom ? 1 : -1;
				var moved = topToBottom ? tokenOne : tokenTwo;
				var target = topToBottom ? tokenTwo : tokenOne;
				var movedProperties = extractProperties(moved);

				while (from != to) {
				  var traversedProperties = extractProperties(tokens[from]);
				  from += delta;

				  // traversed then moved as we move selectors towards the start
				  var reorderable = topToBottom ?
					canReorder(movedProperties, traversedProperties) :
					canReorder(traversedProperties, movedProperties);

				  if (!reorderable && !topToBottom)
					continue selectorIterator;
				  if (!reorderable && topToBottom)
					continue directionIterator;
				}

				var joinAt = topToBottom ? [target.body.length] : [moved.body.length];
				var joinedBodies = topToBottom ? moved.body.concat(target.body) : target.body.concat(moved.body);
				var newBody = this.propertyOptimizer.process(target.value, joinedBodies, joinAt, true);
				changeBodyOf(target, newBody);
				changeBodyOf(moved, { tokenized: [], list: [] });
			  }
			}
		  }
		};

		AdvancedOptimizer.prototype.mergeNonAdjacentByBody = function (tokens) {
		  var candidates = {};
		  var adjacentSpace = this.options.compatibility.selectors.adjacentSpace;

		  for (var i = tokens.length - 1; i >= 0; i--) {
			var token = tokens[i];
			if (token.kind != 'selector')
			  continue;

			if (token.body.length > 0 && unsafeSelector(token.metadata.selector))
			  candidates = {};

			var oldToken = candidates[token.metadata.body];
			if (oldToken && !this.isSpecial(token.metadata.selector) && !this.isSpecial(oldToken.metadata.selector)) {
			  changeSelectorOf(
				token,
				CleanUp.selectors(oldToken.value.concat(token.value), false, adjacentSpace)
			  );

			  changeBodyOf(oldToken, { tokenized: [], list: [] });
			  candidates[token.metadata.body] = null;
			}

			candidates[token.metadata.body] = token;
		  }
		};

		AdvancedOptimizer.prototype.restructure = function (tokens) {
		  var movableTokens = {};
		  var movedProperties = [];
		  var multiPropertyMoveCache = {};
		  var movedToBeDropped = [];
		  var self = this;
		  var maxCombinationsLevel = 2;
		  var ID_JOIN_CHARACTER = '%';

		  function sendToMultiPropertyMoveCache(position, movedProperty, allFits) {
			for (var i = allFits.length - 1; i >= 0; i--) {
			  var fit = allFits[i][0];
			  var id = addToCache(movedProperty, fit);

			  if (multiPropertyMoveCache[id].length > 1 && processMultiPropertyMove(position, multiPropertyMoveCache[id])) {
				removeAllMatchingFromCache(id);
				break;
			  }
			}
		  }

		  function addToCache(movedProperty, fit) {
			var id = cacheId(fit);
			multiPropertyMoveCache[id] = multiPropertyMoveCache[id] || [];
			multiPropertyMoveCache[id].push([movedProperty, fit]);
			return id;
		  }

		  function removeAllMatchingFromCache(matchId) {
			var matchSelectors = matchId.split(ID_JOIN_CHARACTER);
			var forRemoval = [];
			var i;

			for (var id in multiPropertyMoveCache) {
			  var selectors = id.split(ID_JOIN_CHARACTER);
			  for (i = selectors.length - 1; i >= 0; i--) {
				if (matchSelectors.indexOf(selectors[i]) > -1) {
				  forRemoval.push(id);
				  break;
				}
			  }
			}

			for (i = forRemoval.length - 1; i >= 0; i--) {
			  delete multiPropertyMoveCache[forRemoval[i]];
			}
		  }

		  function cacheId(cachedTokens) {
			var id = [];
			for (var i = 0, l = cachedTokens.length; i < l; i++) {
			  id.push(cachedTokens[i].metadata.selector);
			}
			return id.join(ID_JOIN_CHARACTER);
		  }

		  function tokensToMerge(sourceTokens) {
			var uniqueTokensWithBody = [];
			var mergeableTokens = [];

			for (var i = sourceTokens.length - 1; i >= 0; i--) {
			  if (self.isSpecial(sourceTokens[i].metadata.selector))
				continue;

			  mergeableTokens.unshift(sourceTokens[i]);
			  if (sourceTokens[i].body.length > 0 && uniqueTokensWithBody.indexOf(sourceTokens[i]) == -1)
				uniqueTokensWithBody.push(sourceTokens[i]);
			}

			return uniqueTokensWithBody.length > 1 ?
			  mergeableTokens :
			  [];
		  }

		  function shortenIfPossible(position, movedProperty) {
			var name = movedProperty[0];
			var value = movedProperty[1];
			var key = movedProperty[3];
			var valueSize = name.length + value.length + 1;
			var allSelectors = [];
			var qualifiedTokens = [];

			var mergeableTokens = tokensToMerge(movableTokens[key]);
			if (mergeableTokens.length < 2)
			  return;

			var allFits = findAllFits(mergeableTokens, valueSize, 1);
			var bestFit = allFits[0];
			if (bestFit[1] > 0)
			  return sendToMultiPropertyMoveCache(position, movedProperty, allFits);

			for (var i = bestFit[0].length - 1; i >=0; i--) {
			  allSelectors = bestFit[0][i].value.concat(allSelectors);
			  qualifiedTokens.unshift(bestFit[0][i]);
			}

			allSelectors = CleanUp.selectorDuplicates(allSelectors);
			dropAsNewTokenAt(position, [movedProperty], allSelectors, qualifiedTokens);
		  }

		  function fitSorter(fit1, fit2) {
			return fit1[1] > fit2[1];
		  }

		  function findAllFits(mergeableTokens, propertySize, propertiesCount) {
			var combinations = allCombinations(mergeableTokens, propertySize, propertiesCount, maxCombinationsLevel - 1);
			return combinations.sort(fitSorter);
		  }

		  function allCombinations(tokensVariant, propertySize, propertiesCount, level) {
			var differenceVariants = [[tokensVariant, sizeDifference(tokensVariant, propertySize, propertiesCount)]];
			if (tokensVariant.length > 2 && level > 0) {
			  for (var i = tokensVariant.length - 1; i >= 0; i--) {
				var subVariant = Array.prototype.slice.call(tokensVariant, 0);
				subVariant.splice(i, 1);
				differenceVariants = differenceVariants.concat(allCombinations(subVariant, propertySize, propertiesCount, level - 1));
			  }
			}

			return differenceVariants;
		  }

		  function sizeDifference(tokensVariant, propertySize, propertiesCount) {
			var allSelectorsSize = 0;
			for (var i = tokensVariant.length - 1; i >= 0; i--) {
			  allSelectorsSize += tokensVariant[i].body.length > propertiesCount ? tokensVariant[i].metadata.selector.length : -1;
			}
			return allSelectorsSize - (tokensVariant.length - 1) * propertySize + 1;
		  }

		  function dropAsNewTokenAt(position, properties, allSelectors, mergeableTokens) {
			var bodyMetadata = {};
			var i, j, k, m;

			for (i = mergeableTokens.length - 1; i >= 0; i--) {
			  var mergeableToken = mergeableTokens[i];

			  for (j = mergeableToken.body.length - 1; j >= 0; j--) {

				for (k = 0, m = properties.length; k < m; k++) {
				  var property = properties[k];

				  if (mergeableToken.body[j].value === property[3]) {
					bodyMetadata[property[3]] = mergeableToken.body[j].metadata;

					mergeableToken.body.splice(j, 1);
					mergeableToken.metadata.bodiesList.splice(j, 1);
					mergeableToken.metadata.body = mergeableToken.metadata.bodiesList.join(';');
					break;
				  }
				}
			  }
			}

			var newToken = { kind: 'selector', metadata: {} };
			var allBodies = { tokenized: [], list: [] };

			for (i = properties.length - 1; i >= 0; i--) {
			  allBodies.tokenized.push({ value: properties[i][3] });
			  allBodies.list.push(properties[i][3]);
			}

			changeSelectorOf(newToken, allSelectors);
			changeBodyOf(newToken, allBodies);

			for (i = properties.length - 1; i >= 0; i--) {
			  newToken.body[i].metadata = bodyMetadata[properties[i][3]];
			}

			tokens.splice(position, 0, newToken);
		  }

		  function dropPropertiesAt(position, movedProperty) {
			var key = movedProperty[3];

			if (movableTokens[key] && movableTokens[key].length > 1)
			  shortenIfPossible(position, movedProperty);
		  }

		  function processMultiPropertyMove(position, propertiesAndMergableTokens) {
			var valueSize = 0;
			var properties = [];
			var property;

			for (var i = propertiesAndMergableTokens.length - 1; i >= 0; i--) {
			  property = propertiesAndMergableTokens[i][0];
			  var fullValue = property[3];
			  valueSize += fullValue.length + (i > 0 ? 1 : 0);

			  properties.push(property);
			}

			var mergeableTokens = propertiesAndMergableTokens[0][1];
			var bestFit = findAllFits(mergeableTokens, valueSize, properties.length)[0];
			if (bestFit[1] > 0)
			  return false;

			var allSelectors = [];
			var qualifiedTokens = [];
			for (i = bestFit[0].length - 1; i >= 0; i--) {
			  allSelectors = bestFit[0][i].value.concat(allSelectors);
			  qualifiedTokens.unshift(bestFit[0][i]);
			}

			allSelectors = CleanUp.selectorDuplicates(allSelectors);
			dropAsNewTokenAt(position, properties, allSelectors, qualifiedTokens);

			for (i = properties.length - 1; i >= 0; i--) {
			  property = properties[i];
			  var index = movedProperties.indexOf(property);

			  delete movableTokens[property[3]];

			  if (index > -1 && movedToBeDropped.indexOf(index) == -1)
				movedToBeDropped.push(index);
			}

			return true;
		  }

		  for (var i = tokens.length - 1; i >= 0; i--) {
			var token = tokens[i];
			var isSelector;
			var j, k, m;

			if (token.kind == 'selector') {
			  isSelector = true;
			} else if (token.kind == 'block' && !token.isFlatBlock) {
			  isSelector = false;
			} else {
			  continue;
			}

			// We cache movedProperties.length as it may change in the loop
			var movedCount = movedProperties.length;

			var properties = extractProperties(token);
			movedToBeDropped = [];

			var unmovableInCurrentToken = [];
			for (j = properties.length - 1; j >= 0; j--) {
			  for (k = j - 1; k >= 0; k--) {
				if (!canReorderSingle(properties[j], properties[k])) {
				  unmovableInCurrentToken.push(j);
				  break;
				}
			  }
			}

			for (j = 0, m = properties.length; j < m; j++) {
			  var property = properties[j];
			  var movedSameProperty = false;

			  for (k = 0; k < movedCount; k++) {
				var movedProperty = movedProperties[k];

				if (movedToBeDropped.indexOf(k) == -1 && !canReorderSingle(property, movedProperty)) {
				  dropPropertiesAt(i + 1, movedProperty);
				  movedToBeDropped.push(k);
				  delete movableTokens[movedProperty[3]];
				}

				if (!movedSameProperty)
				  movedSameProperty = property[0] == movedProperty[0] && property[1] == movedProperty[1];
			  }

			  if (!isSelector || unmovableInCurrentToken.indexOf(j) > -1)
				continue;

			  var key = property[3];
			  movableTokens[key] = movableTokens[key] || [];
			  movableTokens[key].push(token);

			  if (!movedSameProperty)
				movedProperties.push(property);
			}

			movedToBeDropped = movedToBeDropped.sort(naturalSorter);
			for (j = 0, m = movedToBeDropped.length; j < m; j++) {
			  movedProperties.splice(movedToBeDropped[j] - j, 1);
			}
		  }

		  var position = tokens[0] && tokens[0].kind == 'at-rule' && tokens[0].value.indexOf('@charset') === 0 ? 1 : 0;
		  for (; position < tokens.length - 1; position++) {
			var isImportRule = tokens[position].kind === 'at-rule' && tokens[position].value.indexOf('@import') === 0;
			var isEscapedCommentSpecial = tokens[position].kind === 'text' && tokens[position].value.indexOf('__ESCAPED_COMMENT_SPECIAL') === 0;
			if (!(isImportRule || isEscapedCommentSpecial))
			  break;
		  }

		  for (i = 0; i < movedProperties.length; i++) {
			dropPropertiesAt(position, movedProperties[i]);
		  }
		};

		AdvancedOptimizer.prototype.mergeMediaQueries = function (tokens) {
		  var candidates = {};
		  var reduced = [];

		  for (var i = tokens.length - 1; i >= 0; i--) {
			var token = tokens[i];
			if (token.kind != 'block' || token.isFlatBlock === true)
			  continue;

			var candidate = candidates[token.value];
			if (!candidate) {
			  candidate = [];
			  candidates[token.value] = candidate;
			}

			candidate.push(i);
		  }

		  for (var name in candidates) {
			var positions = candidates[name];

			positionLoop:
			for (var j = positions.length - 1; j > 0; j--) {
			  var source = tokens[positions[j]];
			  var target = tokens[positions[j - 1]];
			  var movedProperties = extractProperties(source);

			  for (var k = positions[j] + 1; k < positions[j - 1]; k++) {
				var traversedProperties = extractProperties(tokens[k]);

				// moved then traversed as we move @media towards the end
				if (!canReorder(movedProperties, traversedProperties))
				  continue positionLoop;
			  }

			  target.body = source.body.concat(target.body);
			  source.body = [];

			  reduced.push(target);
			}
		  }

		  return reduced;
		};

		function optimizeProperties(tokens, propertyOptimizer) {
		  for (var i = 0, l = tokens.length; i < l; i++) {
			var token = tokens[i];

			if (token.kind == 'selector') {
			  changeBodyOf(
				token,
				propertyOptimizer.process(token.value, token.body, false, true)
			  );
			} else if (token.kind == 'block') {
			  optimizeProperties(token.body, propertyOptimizer);
			}
		  }
		}

		AdvancedOptimizer.prototype.optimize = function (tokens) {
		  var self = this;

		  function _optimize(tokens, withRestructuring) {
			tokens.forEach(function (token) {
			  if (token.kind == 'block') {
				var isKeyframes = /@(-moz-|-o-|-webkit-)?keyframes/.test(token.value);
				_optimize(token.body, !isKeyframes);
			  }
			});

			optimizeProperties(tokens, self.propertyOptimizer);

			self.removeDuplicates(tokens);
			self.mergeAdjacent(tokens);
			self.reduceNonAdjacent(tokens);

			self.mergeNonAdjacentBySelector(tokens);
			self.mergeNonAdjacentByBody(tokens);

			if (self.options.restructuring && withRestructuring) {
			  self.restructure(tokens);
			  self.mergeAdjacent(tokens);
			}

			if (self.options.mediaMerging) {
			  var reduced = self.mergeMediaQueries(tokens);
			  for (var i = reduced.length - 1; i >= 0; i--) {
				_optimize(reduced[i].body);
			  }
			}
		  }

		  _optimize(tokens, true);
		};
		
		return AdvancedOptimizer;
	};
	//#endregion
		
	//#region URL: /selectors/optimizer
	modules['/selectors/optimizer'] = function () {
		var Tokenizer = require('/selectors/tokenizer');
		var SimpleOptimizer = require('/selectors/optimizers/simple');
		var AdvancedOptimizer = require('/selectors/optimizers/advanced');

		function SelectorsOptimizer(options, context) {
		  this.options = options || {};
		  this.context = context || {};
		}

		SelectorsOptimizer.prototype.process = function (data, stringifier) {
		  var tokens = new Tokenizer(this.context, this.options.advanced/*, this.options.sourceMap*/).toTokens(data);

		  new SimpleOptimizer(this.options).optimize(tokens);
		  if (this.options.advanced)
			new AdvancedOptimizer(this.options, this.context).optimize(tokens);

		  return stringifier.toString(tokens);
		};
		
		return SelectorsOptimizer;
	};
	//#endregion
	
	//#region URL: /selectors/stringifier
	modules['/selectors/stringifier'] = function () {
		var lineBreak = require('os').EOL;

		function Stringifier(options, restoreCallback) {
		  this.keepBreaks = options.keepBreaks;
		  this.restoreCallback = restoreCallback;
		}

		function valueRebuilder(list, separator) {
		  var merged = '';

		  for (var i = 0, l = list.length; i < l; i++) {
			var el = list[i];

			if (el.value.indexOf('__ESCAPED_') === 0) {
			  merged += el.value;

			  if (i === l - 1) {
				var lastSemicolonAt = merged.lastIndexOf(';');
				merged = merged.substring(0, lastSemicolonAt) + merged.substring(lastSemicolonAt + 1);
			  }
			} else {
			  merged += list[i].value + (i < l - 1 ? separator : '');
			}
		  }

		  return merged;
		}

		function rebuild(tokens, keepBreaks, isFlatBlock) {
		  var joinCharacter = isFlatBlock ? ';' : (keepBreaks ? lineBreak : '');
		  var parts = [];
		  var body;
		  var selector;

		  for (var i = 0, l = tokens.length; i < l; i++) {
			var token = tokens[i];

			if (token.kind === 'text' || token.kind == 'at-rule') {
			  parts.push(token.value);
			  continue;
			}

			// FIXME: broken due to joining/splitting
			if (token.body && (token.body.length === 0 || (token.body.length == 1 && token.body[0].value === '')))
			  continue;

			if (token.kind == 'block') {
			  body = token.isFlatBlock ?
				valueRebuilder(token.body, ';') :
				rebuild(token.body, keepBreaks, token.isFlatBlock);
			  if (body.length > 0)
				parts.push(token.value + '{' + body + '}');
			} else {
			  selector = valueRebuilder(token.value, ',');
			  body = valueRebuilder(token.body, ';');
			  parts.push(selector + '{' + body + '}');
			}
		  }

		  return parts.join(joinCharacter);
		}

		Stringifier.prototype.toString = function (tokens) {
		  var rebuilt = rebuild(tokens, this.keepBreaks, false);

		  return {
			styles: this.restoreCallback(rebuilt).trim()
		  };
		};
		
		return Stringifier;
	};
	//#endregion
	
	//#region URL: /text/escape-store
	modules['/text/escape-store'] = function () {
		var placeholderBrace = '__';

		function EscapeStore(placeholderRoot) {
		  this.placeholderRoot = 'ESCAPED_' + placeholderRoot + '_CLEAN_CSS';
		  this.placeholderToData = {};
		  this.dataToPlaceholder = {};
		  this.count = 0;
		  this.restoreMatcher = new RegExp(this.placeholderRoot + '(\\d+)');
		}

		EscapeStore.prototype._nextPlaceholder = function (metadata) {
		  return {
			index: this.count,
			value: placeholderBrace + this.placeholderRoot + this.count++ + metadata + placeholderBrace
		  };
		};

		EscapeStore.prototype.store = function (data, metadata) {
		  var encodedMetadata = metadata ?
			'(' + metadata.join(',') + ')' :
			'';
		  var placeholder = this.dataToPlaceholder[data];

		  if (!placeholder) {
			var nextPlaceholder = this._nextPlaceholder(encodedMetadata);
			placeholder = nextPlaceholder.value;
			this.placeholderToData[nextPlaceholder.index] = data;
			this.dataToPlaceholder[data] = nextPlaceholder.value;
		  }

		  if (metadata)
			placeholder = placeholder.replace(/\([^\)]+\)/, encodedMetadata);

		  return placeholder;
		};

		EscapeStore.prototype.nextMatch = function (data, cursor) {
		  var next = {};

		  next.start = data.indexOf(this.placeholderRoot, cursor) - placeholderBrace.length;
		  next.end = data.indexOf(placeholderBrace, next.start + placeholderBrace.length) + placeholderBrace.length;
		  if (next.start > -1 && next.end > -1)
			next.match = data.substring(next.start, next.end);

		  return next;
		};

		EscapeStore.prototype.restore = function (placeholder) {
		  var index = this.restoreMatcher.exec(placeholder)[1];
		  return this.placeholderToData[index];
		};
		
		return EscapeStore;
	};
	//#endregion
	
	//#region URL: /utils/quote-scanner
	modules['/utils/quote-scanner'] = function () {
		function QuoteScanner(data) {
		  this.data = data;
		}

		var findQuoteEnd = function (data, matched, cursor, oldCursor) {
		  var commentStartMark = '/*';
		  var commentEndMark = '*/';
		  var escapeMark = '\\';
		  var blockEndMark = '}';
		  var dataPrefix = data.substring(oldCursor, cursor);
		  var commentEndedAt = dataPrefix.lastIndexOf(commentEndMark, cursor);
		  var commentStartedAt = dataPrefix.lastIndexOf(commentStartMark, cursor);
		  var commentStarted = false;

		  if (commentEndedAt >= cursor && commentStartedAt > -1)
			commentStarted = true;
		  if (commentStartedAt < cursor && commentStartedAt > commentEndedAt)
			commentStarted = true;

		  if (commentStarted) {
			var commentEndsAt = data.indexOf(commentEndMark, cursor);
			if (commentEndsAt > -1)
			  return commentEndsAt;

			commentEndsAt = data.indexOf(blockEndMark, cursor);
			return commentEndsAt > -1 ? commentEndsAt - 1 : data.length;
		  }

		  while (true) {
			if (data[cursor] === undefined)
			  break;
			if (data[cursor] == matched && (data[cursor - 1] != escapeMark || data[cursor - 2] == escapeMark))
			  break;

			cursor++;
		  }

		  return cursor;
		};

		function findNext(data, mark, startAt) {
		  var escapeMark = '\\';
		  var candidate = startAt;

		  while (true) {
			candidate = data.indexOf(mark, candidate + 1);
			if (candidate == -1)
			  return -1;
			if (data[candidate - 1] != escapeMark)
			  return candidate;
		  }
		}

		QuoteScanner.prototype.each = function (callback) {
		  var data = this.data;
		  var tempData = [];
		  var nextStart = 0;
		  var nextEnd = 0;
		  var cursor = 0;
		  var matchedMark = null;
		  var singleMark = '\'';
		  var doubleMark = '"';
		  var dataLength = data.length;

		  for (; nextEnd < data.length;) {
			var nextStartSingle = findNext(data, singleMark, nextEnd);
			var nextStartDouble = findNext(data, doubleMark, nextEnd);

			if (nextStartSingle == -1)
			  nextStartSingle = dataLength;
			if (nextStartDouble == -1)
			  nextStartDouble = dataLength;

			if (nextStartSingle < nextStartDouble) {
			  nextStart = nextStartSingle;
			  matchedMark = singleMark;
			} else {
			  nextStart = nextStartDouble;
			  matchedMark = doubleMark;
			}

			if (nextStart == -1)
			  break;

			nextEnd = findQuoteEnd(data, matchedMark, nextStart + 1, cursor);
			if (nextEnd == -1)
			  break;

			var text = data.substring(nextStart, nextEnd + 1);
			tempData.push(data.substring(cursor, nextStart));
			if (text.length > 0)
			  callback(text, tempData, nextStart);

			cursor = nextEnd + 1;
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		};
		
		return QuoteScanner;
	};
	//#endregion
	
	//#region URL: /text/comments-processor
	modules['/text/comments-processor'] = function () {
		var EscapeStore = require('/text/escape-store');
		var QuoteScanner = require('/utils/quote-scanner');

		var SPECIAL_COMMENT_PREFIX = '/*!';
		var COMMENT_PREFIX = '/*';
		var COMMENT_SUFFIX = '*/';

		var lineBreak = require('os').EOL;

		function CommentsProcessor(context, keepSpecialComments, keepBreaks/*, saveWaypoints*/) {
		  this.comments = new EscapeStore('COMMENT');
		  this.specialComments = new EscapeStore('COMMENT_SPECIAL');

		  this.context = context;
		  this.keepAll = keepSpecialComments == '*';
		  this.keepOne = keepSpecialComments == '1' || keepSpecialComments === 1;
		  this.keepBreaks = keepBreaks;
//		  this.saveWaypoints = saveWaypoints;
		}

		function quoteScannerFor(data) {
		  var quoteMap = [];
		  new QuoteScanner(data).each(function (quotedString, _, startsAt) {
			quoteMap.push([startsAt, startsAt + quotedString.length]);
		  });

		  return function (position) {
			for (var i = 0, l = quoteMap.length; i < l; i++) {
			  if (quoteMap[i][0] < position && quoteMap[i][1] > position)
				return true;
			}

			return false;
		  };
		}

		CommentsProcessor.prototype.escape = function (data) {
		  var tempData = [];
		  var nextStart = 0;
		  var nextEnd = 0;
		  var cursor = 0;
		  var indent = 0;
		  var breaksCount;
		  var lastBreakAt;
		  var newIndent;
		  var isQuotedAt = quoteScannerFor(data);
//		  var saveWaypoints = this.saveWaypoints;

		  for (; nextEnd < data.length;) {
			nextStart = data.indexOf(COMMENT_PREFIX, cursor);
			if (nextStart == -1)
			  break;

			if (isQuotedAt(nextStart)) {
			  tempData.push(data.substring(cursor, nextStart + COMMENT_PREFIX.length));
			  cursor = nextStart + COMMENT_PREFIX.length;
			  continue;
			}

			nextEnd = data.indexOf(COMMENT_SUFFIX, nextStart + COMMENT_PREFIX.length);
			if (nextEnd == -1) {
			  this.context.warnings.push('Broken comment: \'' + data.substring(nextStart) + '\'.');
			  nextEnd = data.length - 2;
			}

			tempData.push(data.substring(cursor, nextStart));

			var comment = data.substring(nextStart, nextEnd + COMMENT_SUFFIX.length);
			var isSpecialComment = comment.indexOf(SPECIAL_COMMENT_PREFIX) === 0;

//			if (saveWaypoints) {
//			  breaksCount = comment.split(lineBreak).length - 1;
//			  lastBreakAt = comment.lastIndexOf(lineBreak);
//			  newIndent = lastBreakAt > 0 ?
//				comment.substring(lastBreakAt + lineBreak.length).length :
//				indent + comment.length;
//			}

			if (/*saveWaypoints || */isSpecialComment) {
			  var metadata = /*saveWaypoints ? [breaksCount, newIndent] : */null;
			  var placeholder = isSpecialComment ?
				this.specialComments.store(comment, metadata) :
				this.comments.store(comment, metadata);
			  tempData.push(placeholder);
			}

//			if (saveWaypoints)
//			  indent = newIndent + 1;
			cursor = nextEnd + COMMENT_SUFFIX.length;
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		};

		function restore(context, data, from, isSpecial) {
		  var tempData = [];
		  var restored = 0;
		  var cursor = 0;
		  var addBreak;

		  for (; cursor < data.length;) {
			var nextMatch = from.nextMatch(data, cursor);
			if (nextMatch.start < 0)
			  break;

			tempData.push(data.substring(cursor, nextMatch.start));
			var comment = from.restore(nextMatch.match);

			if (isSpecial && (context.keepAll || (context.keepOne && restored === 0))) {
			  restored++;
			  addBreak = context.keepBreaks && data[nextMatch.end] != '\n' && data.lastIndexOf('\r\n', nextMatch.end + 1) != nextMatch.end;
			  tempData.push(comment, addBreak ? lineBreak : '');
			} else {
			  nextMatch.end += context.keepBreaks ? lineBreak.length : 0;
			}

			cursor = nextMatch.end;
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		}

		CommentsProcessor.prototype.restore = function (data) {
		  data = restore(this, data, this.comments, false);
		  data = restore(this, data, this.specialComments, true);
		  return data;
		};
		
		return CommentsProcessor;
	};
	//#endregion
	
	//#region URL: /text/expressions-processor
	modules['/text/expressions-processor'] = function () {
		var EscapeStore = require('/text/escape-store');

		var EXPRESSION_NAME = 'expression';
		var EXPRESSION_START = '(';
		var EXPRESSION_END = ')';
		var EXPRESSION_PREFIX = EXPRESSION_NAME + EXPRESSION_START;
		var BODY_START = '{';
		var BODY_END = '}';

		var lineBreak = require('os').EOL;

		function findEnd(data, start) {
		  var end = start + EXPRESSION_NAME.length;
		  var level = 0;
		  var quoted = false;
		  var braced = false;

		  while (true) {
			var current = data[end++];

			if (quoted) {
			  quoted = current != '\'' && current != '"';
			} else {
			  quoted = current == '\'' || current == '"';

			  if (current == EXPRESSION_START)
				level++;
			  if (current == EXPRESSION_END)
				level--;
			  if (current == BODY_START)
				braced = true;
			  if (current == BODY_END && !braced && level == 1) {
				end--;
				level--;
			  }
			}

			if (level === 0 && current == EXPRESSION_END)
			  break;
			if (!current) {
			  end = data.substring(0, end).lastIndexOf(BODY_END);
			  break;
			}
		  }

		  return end;
		}

		function ExpressionsProcessor(/*saveWaypoints*/) {
		  this.expressions = new EscapeStore('EXPRESSION');
//		  this.saveWaypoints = saveWaypoints;
		}

		ExpressionsProcessor.prototype.escape = function (data) {
		  var nextStart = 0;
		  var nextEnd = 0;
		  var cursor = 0;
		  var tempData = [];
		  var indent = 0;
		  var breaksCount;
		  var lastBreakAt;
		  var newIndent;
//		  var saveWaypoints = this.saveWaypoints;

		  for (; nextEnd < data.length;) {
			nextStart = data.indexOf(EXPRESSION_PREFIX, nextEnd);
			if (nextStart == -1)
			  break;

			nextEnd = findEnd(data, nextStart);

			var expression = data.substring(nextStart, nextEnd);
//			if (saveWaypoints) {
//			  breaksCount = expression.split(lineBreak).length - 1;
//			  lastBreakAt = expression.lastIndexOf(lineBreak);
//			  newIndent = lastBreakAt > 0 ?
//				expression.substring(lastBreakAt + lineBreak.length).length :
//				indent + expression.length;
//			}

			var metadata = /*saveWaypoints ? [breaksCount, newIndent] : */null;
			var placeholder = this.expressions.store(expression, metadata);
			tempData.push(data.substring(cursor, nextStart));
			tempData.push(placeholder);

//			if (saveWaypoints)
//			  indent = newIndent + 1;
			cursor = nextEnd;
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		};

		ExpressionsProcessor.prototype.restore = function (data) {
		  var tempData = [];
		  var cursor = 0;

		  for (; cursor < data.length;) {
			var nextMatch = this.expressions.nextMatch(data, cursor);
			if (nextMatch.start < 0)
			  break;

			tempData.push(data.substring(cursor, nextMatch.start));
			var comment = this.expressions.restore(nextMatch.match);
			tempData.push(comment);

			cursor = nextMatch.end;
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		};
		
		return ExpressionsProcessor;
	};
	//#endregion
	
	//#region URL: /text/free-text-processor
	modules['/text/free-text-processor'] = function () {
		var EscapeStore = require('/text/escape-store');
		var QuoteScanner = require('/utils/quote-scanner');

		var lineBreak = require('os').EOL;

		function FreeTextProcessor(/*saveWaypoints*/) {
		  this.matches = new EscapeStore('FREE_TEXT');
//		  this.saveWaypoints = saveWaypoints;
		}

		// Strip content tags by replacing them by the a special
		// marker for further restoring. It's done via string scanning
		// instead of regexps to speed up the process.
		FreeTextProcessor.prototype.escape = function(data) {
		  var self = this;
		  var breaksCount;
		  var lastBreakAt;
		  var indent;
		  var metadata;
//		  var saveWaypoints = this.saveWaypoints;

		  return new QuoteScanner(data).each(function(match, store) {
//			if (saveWaypoints) {
//			  breaksCount = match.split(lineBreak).length - 1;
//			  lastBreakAt = match.lastIndexOf(lineBreak);
//			  indent = lastBreakAt > 0 ?
//				match.substring(lastBreakAt + lineBreak.length).length :
//				match.length;
//			  metadata = [breaksCount, indent];
//			}

			var placeholder = self.matches.store(match, metadata);
			store.push(placeholder);
		  });
		};

		function normalize(text, data, cursor) {
		  // FIXME: this is a hack
		  var lastSemicolon = data.lastIndexOf(';', cursor);
		  var lastOpenBrace = data.lastIndexOf('{', cursor);
		  var lastOne = 0;

		  if (lastSemicolon > -1 && lastOpenBrace > -1)
			lastOne = Math.max(lastSemicolon, lastOpenBrace);
		  else if (lastSemicolon == -1)
			lastOne = lastOpenBrace;
		  else
			lastOne = lastSemicolon;

		  var context = data.substring(lastOne + 1, cursor);

		  if (/\[[\w\d\-]+[\*\|\~\^\$]?=$/.test(context))
			text = text.replace(/\\\n|\\\r\n/g, '');

		  if (/^['"][a-zA-Z][a-zA-Z\d\-_]+['"]$/.test(text) && !/format\($/.test(context)) {
			var isFont = /^(font|font\-family):/.test(context);
			var isAttribute = /\[[\w\d\-]+[\*\|\~\^\$]?=$/.test(context);
			var isKeyframe = /@(-moz-|-o-|-webkit-)?keyframes /.test(context);
			var isAnimation = /^(-moz-|-o-|-webkit-)?animation(-name)?:/.test(context);

			if (isFont || isAttribute || isKeyframe || isAnimation)
			  text = text.substring(1, text.length - 1);
		  }

		  return text;
		}

		FreeTextProcessor.prototype.restore = function(data) {
		  var tempData = [];
		  var cursor = 0;

		  for (; cursor < data.length;) {
			var nextMatch = this.matches.nextMatch(data, cursor);
			if (nextMatch.start < 0)
			  break;

			tempData.push(data.substring(cursor, nextMatch.start));
			var text = normalize(this.matches.restore(nextMatch.match), data, nextMatch.start);
			tempData.push(text);

			cursor = nextMatch.end;
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		};
		
		return FreeTextProcessor;
	};
	//#endregion
	
	//#region URL: /text/urls-processor
	modules['/text/urls-processor'] = function () {
		var EscapeStore = require('/text/escape-store');
		var UrlScanner = require('/utils/url-scanner');

		var lineBreak = require('os').EOL;

		function UrlsProcessor(context/*, saveWaypoints*/, removeTrailingSpace) {
		  this.urls = new EscapeStore('URL');
		  this.context = context;
//		  this.saveWaypoints = saveWaypoints;
		  this.removeTrailingSpace = removeTrailingSpace;
		}

		// Strip urls by replacing them by a special
		// marker for further restoring. It's done via string scanning
		// instead of regexps to speed up the process.
		UrlsProcessor.prototype.escape = function (data) {
		  var breaksCount;
		  var lastBreakAt;
		  var indent;
//		  var saveWaypoints = this.saveWaypoints;
		  var self = this;

		  return new UrlScanner(data, this.context).reduce(function (url, tempData) {
//			if (saveWaypoints) {
//			  breaksCount = url.split(lineBreak).length - 1;
//			  lastBreakAt = url.lastIndexOf(lineBreak);
//			  indent = lastBreakAt > 0 ?
//				url.substring(lastBreakAt + lineBreak.length).length :
//				url.length;
//			}

			var placeholder = self.urls.store(url, /*saveWaypoints ? [breaksCount, indent] : */null);
			tempData.push(placeholder);
		  });
		};

		function normalize(url) {
		  url = url
			.replace(/^url/gi, 'url')
			.replace(/\\?\n|\\?\r\n/g, '')
			.replace(/(\s{2,}|\s)/g, ' ')
			.replace(/^url\((['"])? /, 'url($1')
			.replace(/ (['"])?\)$/, '$1)');

		  if (!/url\(.*[\s\(\)].*\)/.test(url) && !/url\(['"]data:[^;]+;charset/.test(url))
			url = url.replace(/["']/g, '');

		  return url;
		}

		UrlsProcessor.prototype.restore = function (data) {
		  var tempData = [];
		  var cursor = 0;

		  for (; cursor < data.length;) {
			var nextMatch = this.urls.nextMatch(data, cursor);
			if (nextMatch.start < 0)
			  break;

			tempData.push(data.substring(cursor, nextMatch.start));
			var url = normalize(this.urls.restore(nextMatch.match));
			tempData.push(url);

			cursor = nextMatch.end + (this.removeTrailingSpace && data[nextMatch.end] == ' ' ? 1 : 0);
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		};
		
		return UrlsProcessor;
	};
	//#endregion
	
	//#region URL: /utils/url-scanner
	modules['/utils/url-scanner'] = function () {
		var URL_PREFIX = 'url(';
		var UPPERCASE_URL_PREFIX = 'URL(';
		var URL_SUFFIX = ')';

		function UrlScanner(data, context) {
		  this.data = data;
		  this.context = context;
		}

		UrlScanner.prototype.reduce = function (callback) {
		  var nextStart = 0;
		  var nextStartUpperCase = 0;
		  var nextEnd = 0;
		  var cursor = 0;
		  var tempData = [];
		  var data = this.data;
		  var hasUppercaseUrl = data.indexOf(UPPERCASE_URL_PREFIX) > -1;

		  for (; nextEnd < data.length;) {
			nextStart = data.indexOf(URL_PREFIX, nextEnd);
			nextStartUpperCase = hasUppercaseUrl ? data.indexOf(UPPERCASE_URL_PREFIX, nextEnd) : -1;
			if (nextStart == -1 && nextStartUpperCase == -1)
			  break;

			if (nextStart == -1 && nextStartUpperCase > -1)
			  nextStart = nextStartUpperCase;

			if (data[nextStart + URL_PREFIX.length] == '"')
			  nextEnd = data.indexOf('"', nextStart + URL_PREFIX.length + 1);
			else if (data[nextStart + URL_PREFIX.length] == '\'')
			  nextEnd = data.indexOf('\'', nextStart + URL_PREFIX.length + 1);
			else
			  nextEnd = data.indexOf(URL_SUFFIX, nextStart);

			// Following lines are a safety mechanism to ensure
			// incorrectly terminated urls are processed correctly.
			if (nextEnd == -1) {
			  nextEnd = data.indexOf('}', nextStart);

			  if (nextEnd == -1)
				nextEnd = data.length;
			  else
				nextEnd--;

			  this.context.warnings.push('Broken URL declaration: \'' + data.substring(nextStart, nextEnd + 1) + '\'.');
			} else {
			  if (data[nextEnd] != URL_SUFFIX)
				nextEnd = data.indexOf(URL_SUFFIX, nextEnd);
			}

			tempData.push(data.substring(cursor, nextStart));

			var url = data.substring(nextStart, nextEnd + 1);
			callback(url, tempData);

			cursor = nextEnd + 1;
		  }

		  return tempData.length > 0 ?
			tempData.join('') + data.substring(cursor, data.length) :
			data;
		};

		return UrlScanner;
	};
	//#endregion
	
	//#region URL: /utils/compatibility
	modules['/utils/compatibility'] = function () {
		var util = require('util');

		var DEFAULTS = {
		  '*': {
			colors: {
			  opacity: true // rgba / hsla
			},
			properties: {
			  backgroundSizeMerging: false, // background-size to shorthand
			  iePrefixHack: false, // underscore / asterisk prefix hacks on IE
			  ieSuffixHack: false, // \9 suffix hacks on IE
			  merging: true, // merging properties into one
			  spaceAfterClosingBrace: false // 'url() no-repeat' to 'url()no-repeat'
			},
			selectors: {
			  adjacentSpace: false, // div+ nav Android stock browser hack
			  ie7Hack: false, // *+html hack
			  special: /(\-moz\-|\-ms\-|\-o\-|\-webkit\-|:dir\([a-z-]*\)|:first(?![a-z-])|:fullscreen|:left|:read-only|:read-write|:right)/ // special selectors which prevent merging
			},
			units: {
			  rem: true
			}
		  },
		  'ie8': {
			colors: {
			  opacity: false
			},
			properties: {
			  backgroundSizeMerging: false,
			  iePrefixHack: true,
			  ieSuffixHack: true,
			  merging: false,
			  spaceAfterClosingBrace: true
			},
			selectors: {
			  adjacentSpace: false,
			  ie7Hack: false,
			  special: /(\-moz\-|\-ms\-|\-o\-|\-webkit\-|:root|:nth|:first\-of|:last|:only|:empty|:target|:checked|::selection|:enabled|:disabled|:not)/
			},
			units: {
			  rem: false
			}
		  },
		  'ie7': {
			colors: {
			  opacity: false
			},
			properties: {
			  backgroundSizeMerging: false,
			  iePrefixHack: true,
			  ieSuffixHack: true,
			  merging: false,
			  spaceAfterClosingBrace: true
			},
			selectors: {
			  adjacentSpace: false,
			  ie7Hack: true,
			  special: /(\-moz\-|\-ms\-|\-o\-|\-webkit\-|:focus|:before|:after|:root|:nth|:first\-of|:last|:only|:empty|:target|:checked|::selection|:enabled|:disabled|:not)/
			},
			units: {
			  rem: false
			}
		  }
		};

		function Compatibility(source) {
		  this.source = source || {};
		}

		function merge(source, target) {
		  for (var key in source) {
			var value = source[key];

			if (typeof value === 'object' && !util.isRegExp(value))
			  target[key] = merge(value, target[key] || {});
			else
			  target[key] = key in target ? target[key] : value;
		  }

		  return target;
		}

		function calculateSource(source) {
		  if (typeof source == 'object')
			return source;

		  if (!/[,\+\-]/.test(source))
			return DEFAULTS[source] || DEFAULTS['*'];

		  var parts = source.split(',');
		  var template = parts[0] in DEFAULTS ?
			DEFAULTS[parts.shift()] :
			DEFAULTS['*'];

		  source = {};

		  parts.forEach(function (part) {
			var isAdd = part[0] == '+';
			var key = part.substring(1).split('.');
			var group = key[0];
			var option = key[1];

			source[group] = source[group] || {};
			source[group][option] = isAdd;
		  });

		  return merge(template, source);
		}

		Compatibility.prototype.toOptions = function () {
		  return merge(DEFAULTS['*'], calculateSource(this.source));
		};
		
		return Compatibility;
	};
	//#endregion
	
	//#region URL: /utils/source-tracker
	modules['/utils/source-tracker'] = function () {
		function SourceTracker() {
		  this.sources = [];
		}

		SourceTracker.prototype.store = function (filename, data) {
		  this.sources.push(filename);

		  return '__ESCAPED_SOURCE_CLEAN_CSS' + (this.sources.length - 1) + '__' +
			data +
			'__ESCAPED_SOURCE_END_CLEAN_CSS__';
		};

		SourceTracker.prototype.nextStart = function (data) {
		  var next = /__ESCAPED_SOURCE_CLEAN_CSS(\d+)__/.exec(data);

		  return next ?
			{ index: next.index, filename: this.sources[~~next[1]] } :
			null;
		};

		SourceTracker.prototype.nextEnd = function (data) {
		  return /__ESCAPED_SOURCE_END_CLEAN_CSS__/g.exec(data);
		};

		SourceTracker.prototype.removeAll = function (data) {
		  return data
			.replace(/__ESCAPED_SOURCE_CLEAN_CSS\d+__/g, '')
			.replace(/__ESCAPED_SOURCE_END_CLEAN_CSS__/g, '');
		};
		
		return SourceTracker;
	};
	//#endregion
	
	//#region URL: /utils/source-reader
	modules['/utils/source-reader'] = function () {
//		var path = require('path');
//		var UrlRewriter = require('/images/url-rewriter');

		function SourceReader(context, data) {
		  this.outerContext = context;
		  this.data = data;
		}

		SourceReader.prototype.toString = function () {
		  if (typeof this.data == 'string')
			return this.data;
		  if (Buffer.isBuffer(this.data))
			return this.data.toString();
		  if (Array.isArray(this.data))
			return fromArray(this.outerContext, this.data);

		  return fromHash(this.outerContext, this.data);
		};

		function fromArray(outerContext, sources) {
		  return sources
			.map(function (source) {
			  return outerContext.options.processImport === false ?
				source + '@shallow' :
				source;
			})
//			.map(function (source) {
//			  return !outerContext.options.relativeTo || /^https?:\/\//.test(source) ?
//				source :
//				path.relative(outerContext.options.relativeTo, source);
//			})
			.map(function (source) { return '@import url(' + source + ');'; })
			.join('');
		}

		function fromHash(outerContext, sources) {
		  var data = [];
		  var toBase = path.resolve(outerContext.options.target || process.cwd());

		  for (var source in sources) {
			var styles = sources[source].styles;
//			var inputSourceMap = sources[source].sourceMap;

//			var rewriter = new UrlRewriter({
//			  absolute: !!outerContext.options.root,
//			  relative: !outerContext.options.root,
//			  imports: true,
//			  urls: outerContext.options.rebase,
//			  fromBase: path.dirname(path.resolve(source)),
//			  toBase: toBase
//			}, this.outerContext);
//			styles = rewriter.process(styles);

//			if (outerContext.options.sourceMap && inputSourceMap) {
//			  var absoluteSource = path.resolve(source);
//			  styles = outerContext.sourceTracker.store(absoluteSource, styles);
//			  outerContext.inputSourceMapTracker.trackLoaded(absoluteSource, inputSourceMap);
//			}

			data.push(styles);
		  }

		  return data.join('');
		}

		return SourceReader;
	};
	//#endregion
	
	//#region URL: /clean
	modules['/clean'] = function () {
//		var ImportInliner = require('/imports/inliner');
//		var UrlRebase = require('/images/url-rebase');
		var SelectorsOptimizer = require('/selectors/optimizer');
		var Stringifier = require('/selectors/stringifier');
//		var SourceMapStringifier = require('/selectors/source-map-stringifier');

		var CommentsProcessor = require('/text/comments-processor');
		var ExpressionsProcessor = require('/text/expressions-processor');
		var FreeTextProcessor = require('/text/free-text-processor');
		var UrlsProcessor = require('/text/urls-processor');

		var Compatibility = require('/utils/compatibility');
//		var InputSourceMapTracker = require('/utils/input-source-map-tracker');
		var SourceTracker = require('/utils/source-tracker');
		var SourceReader = require('/utils/source-reader');

		var DEFAULT_TIMEOUT = 5000;

		var CleanCSS = function CleanCSS(options) {
		  options = options || {};

		  this.options = {
			advanced: undefined === options.advanced ? true : !!options.advanced,
			aggressiveMerging: undefined === options.aggressiveMerging ? true : !!options.aggressiveMerging,
//			benchmark: options.benchmark,
			compatibility: new Compatibility(options.compatibility).toOptions(),
//			debug: options.debug,
//			inliner: options.inliner || {},
			keepBreaks: options.keepBreaks || false,
			keepSpecialComments: 'keepSpecialComments' in options ? options.keepSpecialComments : '*',
			mediaMerging: undefined === options.mediaMerging ? true : !!options.mediaMerging,
			processImport: undefined === options.processImport ? true : !!options.processImport,
			rebase: undefined === options.rebase ? true : !!options.rebase,
			relativeTo: options.relativeTo,
			restructuring: undefined === options.restructuring ? true : !!options.restructuring,
			root: options.root,
			roundingPrecision: options.roundingPrecision,
			shorthandCompacting: /*!!options.sourceMap ? false : */(undefined === options.shorthandCompacting ? true : !!options.shorthandCompacting),
//			sourceMap: options.sourceMap,
			target: options.target
		  };

//		  this.options.inliner.timeout = this.options.inliner.timeout || DEFAULT_TIMEOUT;
//		  this.options.inliner.request = this.options.inliner.request || {};
		};

		CleanCSS.prototype.minify = function(data, callback) {
		  var context = {
//			stats: {},
			errors: [],
			warnings: [],
			options: this.options,
//			debug: this.options.debug,
			sourceTracker: new SourceTracker()
		  };

//		  if (context.options.sourceMap)
//			context.inputSourceMapTracker = new InputSourceMapTracker(context);

		  data = new SourceReader(context, data).toString();

//		  if (context.options.processImport || data.indexOf('@shallow') > 0) {
//			// inline all imports
//			var runner = callback ?
//			  process.nextTick :
//			  function (callback) { return callback(); };
//
//			return runner(function () {
//			  return new ImportInliner(context).process(data, {
//				localOnly: !callback,
//				whenDone: runMinifier(callback, context)
//			  });
//			});
//		  } else {
			return runMinifier(callback, context)(data);
//		  }
		};

		function runMinifier(callback, context) {
		  function whenSourceMapReady (data) {
			data = /*context.options.debug ?
			  minifyWithDebug(context, data) :
			  */minify(context, data);
			data = withMetadata(context, data);

			return callback ?
			  callback.call(null, context.errors.length > 0 ? context.errors : null, data) :
			  data;
		  }

		  return function (data) {
//			if (context.options.sourceMap) {
//			  return context.inputSourceMapTracker.track(data, function () { return whenSourceMapReady(data); });
//			} else {
			  return whenSourceMapReady(data);
//			}
		  };
		}

		function withMetadata(context, data) {
//		  data.stats = context.stats;
		  data.errors = context.errors;
		  data.warnings = context.warnings;
		  return data;
		}

//		function minifyWithDebug(context, data) {
//		  var startedAt = process.hrtime();
//		  context.stats.originalSize = context.sourceTracker.removeAll(data).length;
//
//		  data = minify(context, data);
//
//		  var elapsed = process.hrtime(startedAt);
//		  context.stats.timeSpent = ~~(elapsed[0] * 1e3 + elapsed[1] / 1e6);
//		  context.stats.efficiency = 1 - data.styles.length / context.stats.originalSize;
//		  context.stats.minifiedSize = data.styles.length;
//
//		  return data;
//		}

//		function benchmark(runner) {
//		  return function (processor, action) {
//			var name =  processor.constructor.name + '#' + action;
//			var start = process.hrtime();
//			runner(processor, action);
//			var itTook = process.hrtime(start);
//			console.log('%d ms: ' + name, 1000 * itTook[0] + itTook[1] / 1000000);
//		  };
//		}

		function minify(context, data) {
		  var options = context.options;
//		  var sourceMapTracker = context.inputSourceMapTracker;

		  var commentsProcessor = new CommentsProcessor(context, options.keepSpecialComments, options.keepBreaks/*, options.sourceMap*/);
		  var expressionsProcessor = new ExpressionsProcessor(/*options.sourceMap*/);
		  var freeTextProcessor = new FreeTextProcessor(/*options.sourceMap*/);
		  var urlsProcessor = new UrlsProcessor(context/*, options.sourceMap*/, !options.compatibility.properties.spaceAfterClosingBrace);

//		  var urlRebase = new UrlRebase(context);
		  var selectorsOptimizer = new SelectorsOptimizer(options, context);
		  var stringifierClass = /*options.sourceMap ? SourceMapStringifier : */Stringifier;

		  var run = function (processor, action) {
			data = typeof processor == 'function' ?
			  processor(data) :
			  processor[action](data);
		  };

//		  if (options.benchmark)
//			run = benchmark(run);

		  run(commentsProcessor, 'escape');
		  run(expressionsProcessor, 'escape');
		  run(urlsProcessor, 'escape');
		  run(freeTextProcessor, 'escape');

		  run(function() {
			var stringifier = new stringifierClass(options, function (data) {
			  data = freeTextProcessor.restore(data);
			  data = urlsProcessor.restore(data);
//			  data = options.rebase ? urlRebase.process(data) : data;
			  data = expressionsProcessor.restore(data);
			  return commentsProcessor.restore(data);
			}/*, sourceMapTracker*/);

			return selectorsOptimizer.process(data, stringifier);
		  });

		  return data;
		}
		
		return CleanCSS;
	};
	//#endregion
	
	return require('/clean');
})();
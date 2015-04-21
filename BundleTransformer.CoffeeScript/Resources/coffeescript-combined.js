/*!
 * CoffeeScript Compiler v1.9.2
 * http://coffeescript.org
 *
 * Copyright 2009-2015, Jeremy Ashkenas
 * Released under the MIT License
 */
var CoffeeScript = (function(){
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

	//#region URL: /helpers
	modules['/helpers'] = function() {
	  var exports = {};
	  var buildLocationData, extend, flatten, ref, repeat, syntaxErrorToString;

	  exports.starts = function(string, literal, start) {
		return literal === string.substr(start, literal.length);
	  };

	  exports.ends = function(string, literal, back) {
		var len;
		len = literal.length;
		return literal === string.substr(string.length - len - (back || 0), len);
	  };

	  exports.repeat = repeat = function(str, n) {
		var res;
		res = '';
		while (n > 0) {
		  if (n & 1) {
			res += str;
		  }
		  n >>>= 1;
		  str += str;
		}
		return res;
	  };

	  exports.compact = function(array) {
		var i, item, len1, results;
		results = [];
		for (i = 0, len1 = array.length; i < len1; i++) {
		  item = array[i];
		  if (item) {
			results.push(item);
		  }
		}
		return results;
	  };

	  exports.count = function(string, substr) {
		var num, pos;
		num = pos = 0;
		if (!substr.length) {
		  return 1 / 0;
		}
		while (pos = 1 + string.indexOf(substr, pos)) {
		  num++;
		}
		return num;
	  };

	  exports.merge = function(options, overrides) {
		return extend(extend({}, options), overrides);
	  };

	  extend = exports.extend = function(object, properties) {
		var key, val;
		for (key in properties) {
		  val = properties[key];
		  object[key] = val;
		}
		return object;
	  };

	  exports.flatten = flatten = function(array) {
		var element, flattened, i, len1;
		flattened = [];
		for (i = 0, len1 = array.length; i < len1; i++) {
		  element = array[i];
		  if (element instanceof Array) {
			flattened = flattened.concat(flatten(element));
		  } else {
			flattened.push(element);
		  }
		}
		return flattened;
	  };

	  exports.del = function(obj, key) {
		var val;
		val = obj[key];
		delete obj[key];
		return val;
	  };

	  exports.some = (ref = Array.prototype.some) != null ? ref : function(fn) {
		var e, i, len1;
		for (i = 0, len1 = this.length; i < len1; i++) {
		  e = this[i];
		  if (fn(e)) {
			return true;
		  }
		}
		return false;
	  };

	  exports.invertLiterate = function(code) {
		var line, lines, maybe_code;
		maybe_code = true;
		lines = (function() {
		  var i, len1, ref1, results;
		  ref1 = code.split('\n');
		  results = [];
		  for (i = 0, len1 = ref1.length; i < len1; i++) {
			line = ref1[i];
			if (maybe_code && /^([ ]{4}|[ ]{0,3}\t)/.test(line)) {
			  results.push(line);
			} else if (maybe_code = /^\s*$/.test(line)) {
			  results.push(line);
			} else {
			  results.push('# ' + line);
			}
		  }
		  return results;
		})();
		return lines.join('\n');
	  };

	  buildLocationData = function(first, last) {
		if (!last) {
		  return first;
		} else {
		  return {
			first_line: first.first_line,
			first_column: first.first_column,
			last_line: last.last_line,
			last_column: last.last_column
		  };
		}
	  };

	  exports.addLocationDataFn = function(first, last) {
		return function(obj) {
		  if (((typeof obj) === 'object') && (!!obj['updateLocationDataIfMissing'])) {
			obj.updateLocationDataIfMissing(buildLocationData(first, last));
		  }
		  return obj;
		};
	  };

	  exports.locationDataToString = function(obj) {
		var locationData;
		if (("2" in obj) && ("first_line" in obj[2])) {
		  locationData = obj[2];
		} else if ("first_line" in obj) {
		  locationData = obj;
		}
		if (locationData) {
		  return ((locationData.first_line + 1) + ":" + (locationData.first_column + 1) + "-") + ((locationData.last_line + 1) + ":" + (locationData.last_column + 1));
		} else {
		  return "No location data";
		}
	  };

	  exports.baseFileName = function(file, stripExt, useWinPathSep) {
		var parts, pathSep;
		if (stripExt == null) {
		  stripExt = false;
		}
		if (useWinPathSep == null) {
		  useWinPathSep = false;
		}
		pathSep = useWinPathSep ? /\\|\// : /\//;
		parts = file.split(pathSep);
		file = parts[parts.length - 1];
		if (!(stripExt && file.indexOf('.') >= 0)) {
		  return file;
		}
		parts = file.split('.');
		parts.pop();
		if (parts[parts.length - 1] === 'coffee' && parts.length > 1) {
		  parts.pop();
		}
		return parts.join('.');
	  };

	  exports.isCoffee = function(file) {
		return /\.((lit)?coffee|coffee\.md)$/.test(file);
	  };

	  exports.isLiterate = function(file) {
		return /\.(litcoffee|coffee\.md)$/.test(file);
	  };

	  exports.throwSyntaxError = function(message, location) {
		var error;
		error = new SyntaxError(message);
		error.location = location;
		error.toString = syntaxErrorToString;
		error.stack = error.toString();
		throw error;
	  };

	  exports.updateSyntaxError = function(error, code, filename) {
		if (error.toString === syntaxErrorToString) {
		  error.code || (error.code = code);
		  error.filename || (error.filename = filename);
		  error.stack = error.toString();
		}
		return error;
	  };

	  syntaxErrorToString = function() {
		var codeLine, colorize, colorsEnabled, end, filename, first_column, first_line, last_column, last_line, marker, ref1, ref2, ref3, ref4, start;
		if (!(this.code && this.location)) {
		  return Error.prototype.toString.call(this);
		}
		ref1 = this.location, first_line = ref1.first_line, first_column = ref1.first_column, last_line = ref1.last_line, last_column = ref1.last_column;
		if (last_line == null) {
		  last_line = first_line;
		}
		if (last_column == null) {
		  last_column = first_column;
		}
		filename = this.filename || '[stdin]';
		codeLine = this.code.split('\n')[first_line];
		start = first_column;
		end = first_line === last_line ? last_column + 1 : codeLine.length;
		marker = codeLine.slice(0, start).replace(/[^\s]/g, ' ') + repeat('^', end - start);
		if (typeof process !== "undefined" && process !== null) {
		  colorsEnabled = ((ref2 = process.stdout) != null ? ref2.isTTY : void 0) && !((ref3 = process.env) != null ? ref3.NODE_DISABLE_COLORS : void 0);
		}
		if ((ref4 = this.colorful) != null ? ref4 : colorsEnabled) {
		  colorize = function(str) {
			return "\x1B[1;31m" + str + "\x1B[0m";
		  };
		  codeLine = codeLine.slice(0, start) + colorize(codeLine.slice(start, end)) + codeLine.slice(end);
		  marker = colorize(marker);
		}
		return filename + ":" + (first_line + 1) + ":" + (first_column + 1) + ": error: " + this.message + "\n" + codeLine + "\n" + marker;
	  };

	  exports.nameWhitespaceCharacter = function(string) {
		switch (string) {
		  case ' ':
			return 'space';
		  case '\n':
			return 'newline';
		  case '\r':
			return 'carriage return';
		  case '\t':
			return 'tab';
		  default:
			return string;
		}
	  };

	  return exports;
	};
	//#endregion

	//#region URL: /rewriter
	modules['/rewriter'] = function() {
	  var exports = {};
	  var BALANCED_PAIRS, CALL_CLOSERS, EXPRESSION_CLOSE, EXPRESSION_END, EXPRESSION_START, IMPLICIT_CALL, IMPLICIT_END, IMPLICIT_FUNC, IMPLICIT_UNSPACED_CALL, INVERSES, LINEBREAKS, SINGLE_CLOSERS, SINGLE_LINERS, generate, k, left, len, ref, rite,
		indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; },
		slice = [].slice;

	  generate = function(tag, value, origin) {
		var tok;
		tok = [tag, value];
		tok.generated = true;
		if (origin) {
		  tok.origin = origin;
		}
		return tok;
	  };

	  exports.Rewriter = (function() {
		function Rewriter() {}

		Rewriter.prototype.rewrite = function(tokens1) {
		  this.tokens = tokens1;
		  this.removeLeadingNewlines();
		  this.closeOpenCalls();
		  this.closeOpenIndexes();
		  this.normalizeLines();
		  this.tagPostfixConditionals();
		  this.addImplicitBracesAndParens();
		  this.addLocationDataToGeneratedTokens();
		  return this.tokens;
		};

		Rewriter.prototype.scanTokens = function(block) {
		  var i, token, tokens;
		  tokens = this.tokens;
		  i = 0;
		  while (token = tokens[i]) {
			i += block.call(this, token, i, tokens);
		  }
		  return true;
		};

		Rewriter.prototype.detectEnd = function(i, condition, action) {
		  var levels, ref, ref1, token, tokens;
		  tokens = this.tokens;
		  levels = 0;
		  while (token = tokens[i]) {
			if (levels === 0 && condition.call(this, token, i)) {
			  return action.call(this, token, i);
			}
			if (!token || levels < 0) {
			  return action.call(this, token, i - 1);
			}
			if (ref = token[0], indexOf.call(EXPRESSION_START, ref) >= 0) {
			  levels += 1;
			} else if (ref1 = token[0], indexOf.call(EXPRESSION_END, ref1) >= 0) {
			  levels -= 1;
			}
			i += 1;
		  }
		  return i - 1;
		};

		Rewriter.prototype.removeLeadingNewlines = function() {
		  var i, k, len, ref, tag;
		  ref = this.tokens;
		  for (i = k = 0, len = ref.length; k < len; i = ++k) {
			tag = ref[i][0];
			if (tag !== 'TERMINATOR') {
			  break;
			}
		  }
		  if (i) {
			return this.tokens.splice(0, i);
		  }
		};

		Rewriter.prototype.closeOpenCalls = function() {
		  var action, condition;
		  condition = function(token, i) {
			var ref;
			return ((ref = token[0]) === ')' || ref === 'CALL_END') || token[0] === 'OUTDENT' && this.tag(i - 1) === ')';
		  };
		  action = function(token, i) {
			return this.tokens[token[0] === 'OUTDENT' ? i - 1 : i][0] = 'CALL_END';
		  };
		  return this.scanTokens(function(token, i) {
			if (token[0] === 'CALL_START') {
			  this.detectEnd(i + 1, condition, action);
			}
			return 1;
		  });
		};

		Rewriter.prototype.closeOpenIndexes = function() {
		  var action, condition;
		  condition = function(token, i) {
			var ref;
			return (ref = token[0]) === ']' || ref === 'INDEX_END';
		  };
		  action = function(token, i) {
			return token[0] = 'INDEX_END';
		  };
		  return this.scanTokens(function(token, i) {
			if (token[0] === 'INDEX_START') {
			  this.detectEnd(i + 1, condition, action);
			}
			return 1;
		  });
		};

		Rewriter.prototype.indexOfTag = function() {
		  var fuzz, i, j, k, pattern, ref, ref1;
		  i = arguments[0], pattern = 2 <= arguments.length ? slice.call(arguments, 1) : [];
		  fuzz = 0;
		  for (j = k = 0, ref = pattern.length; 0 <= ref ? k < ref : k > ref; j = 0 <= ref ? ++k : --k) {
			while (this.tag(i + j + fuzz) === 'HERECOMMENT') {
			  fuzz += 2;
			}
			if (pattern[j] == null) {
			  continue;
			}
			if (typeof pattern[j] === 'string') {
			  pattern[j] = [pattern[j]];
			}
			if (ref1 = this.tag(i + j + fuzz), indexOf.call(pattern[j], ref1) < 0) {
			  return -1;
			}
		  }
		  return i + j + fuzz - 1;
		};

		Rewriter.prototype.looksObjectish = function(j) {
		  var end, index;
		  if (this.indexOfTag(j, '@', null, ':') > -1 || this.indexOfTag(j, null, ':') > -1) {
			return true;
		  }
		  index = this.indexOfTag(j, EXPRESSION_START);
		  if (index > -1) {
			end = null;
			this.detectEnd(index + 1, (function(token) {
			  var ref;
			  return ref = token[0], indexOf.call(EXPRESSION_END, ref) >= 0;
			}), (function(token, i) {
			  return end = i;
			}));
			if (this.tag(end + 1) === ':') {
			  return true;
			}
		  }
		  return false;
		};

		Rewriter.prototype.findTagsBackwards = function(i, tags) {
		  var backStack, ref, ref1, ref2, ref3, ref4, ref5;
		  backStack = [];
		  while (i >= 0 && (backStack.length || (ref2 = this.tag(i), indexOf.call(tags, ref2) < 0) && ((ref3 = this.tag(i), indexOf.call(EXPRESSION_START, ref3) < 0) || this.tokens[i].generated) && (ref4 = this.tag(i), indexOf.call(LINEBREAKS, ref4) < 0))) {
			if (ref = this.tag(i), indexOf.call(EXPRESSION_END, ref) >= 0) {
			  backStack.push(this.tag(i));
			}
			if ((ref1 = this.tag(i), indexOf.call(EXPRESSION_START, ref1) >= 0) && backStack.length) {
			  backStack.pop();
			}
			i -= 1;
		  }
		  return ref5 = this.tag(i), indexOf.call(tags, ref5) >= 0;
		};

		Rewriter.prototype.addImplicitBracesAndParens = function() {
		  var stack, start;
		  stack = [];
		  start = null;
		  return this.scanTokens(function(token, i, tokens) {
			var endImplicitCall, endImplicitObject, forward, inImplicit, inImplicitCall, inImplicitControl, inImplicitObject, newLine, nextTag, offset, prevTag, prevToken, ref, ref1, ref2, ref3, ref4, ref5, s, sameLine, stackIdx, stackTag, stackTop, startIdx, startImplicitCall, startImplicitObject, startsLine, tag;
			tag = token[0];
			prevTag = (prevToken = i > 0 ? tokens[i - 1] : [])[0];
			nextTag = (i < tokens.length - 1 ? tokens[i + 1] : [])[0];
			stackTop = function() {
			  return stack[stack.length - 1];
			};
			startIdx = i;
			forward = function(n) {
			  return i - startIdx + n;
			};
			inImplicit = function() {
			  var ref, ref1;
			  return (ref = stackTop()) != null ? (ref1 = ref[2]) != null ? ref1.ours : void 0 : void 0;
			};
			inImplicitCall = function() {
			  var ref;
			  return inImplicit() && ((ref = stackTop()) != null ? ref[0] : void 0) === '(';
			};
			inImplicitObject = function() {
			  var ref;
			  return inImplicit() && ((ref = stackTop()) != null ? ref[0] : void 0) === '{';
			};
			inImplicitControl = function() {
			  var ref;
			  return inImplicit && ((ref = stackTop()) != null ? ref[0] : void 0) === 'CONTROL';
			};
			startImplicitCall = function(j) {
			  var idx;
			  idx = j != null ? j : i;
			  stack.push([
				'(', idx, {
				  ours: true
				}
			  ]);
			  tokens.splice(idx, 0, generate('CALL_START', '('));
			  if (j == null) {
				return i += 1;
			  }
			};
			endImplicitCall = function() {
			  stack.pop();
			  tokens.splice(i, 0, generate('CALL_END', ')', ['', 'end of input', token[2]]));
			  return i += 1;
			};
			startImplicitObject = function(j, startsLine) {
			  var idx, val;
			  if (startsLine == null) {
				startsLine = true;
			  }
			  idx = j != null ? j : i;
			  stack.push([
				'{', idx, {
				  sameLine: true,
				  startsLine: startsLine,
				  ours: true
				}
			  ]);
			  val = new String('{');
			  val.generated = true;
			  tokens.splice(idx, 0, generate('{', val, token));
			  if (j == null) {
				return i += 1;
			  }
			};
			endImplicitObject = function(j) {
			  j = j != null ? j : i;
			  stack.pop();
			  tokens.splice(j, 0, generate('}', '}', token));
			  return i += 1;
			};
			if (inImplicitCall() && (tag === 'IF' || tag === 'TRY' || tag === 'FINALLY' || tag === 'CATCH' || tag === 'CLASS' || tag === 'SWITCH')) {
			  stack.push([
				'CONTROL', i, {
				  ours: true
				}
			  ]);
			  return forward(1);
			}
			if (tag === 'INDENT' && inImplicit()) {
			  if (prevTag !== '=>' && prevTag !== '->' && prevTag !== '[' && prevTag !== '(' && prevTag !== ',' && prevTag !== '{' && prevTag !== 'TRY' && prevTag !== 'ELSE' && prevTag !== '=') {
				while (inImplicitCall()) {
				  endImplicitCall();
				}
			  }
			  if (inImplicitControl()) {
				stack.pop();
			  }
			  stack.push([tag, i]);
			  return forward(1);
			}
			if (indexOf.call(EXPRESSION_START, tag) >= 0) {
			  stack.push([tag, i]);
			  return forward(1);
			}
			if (indexOf.call(EXPRESSION_END, tag) >= 0) {
			  while (inImplicit()) {
				if (inImplicitCall()) {
				  endImplicitCall();
				} else if (inImplicitObject()) {
				  endImplicitObject();
				} else {
				  stack.pop();
				}
			  }
			  start = stack.pop();
			}
			if ((indexOf.call(IMPLICIT_FUNC, tag) >= 0 && token.spaced || tag === '?' && i > 0 && !tokens[i - 1].spaced) && (indexOf.call(IMPLICIT_CALL, nextTag) >= 0 || indexOf.call(IMPLICIT_UNSPACED_CALL, nextTag) >= 0 && !((ref = tokens[i + 1]) != null ? ref.spaced : void 0) && !((ref1 = tokens[i + 1]) != null ? ref1.newLine : void 0))) {
			  if (tag === '?') {
				tag = token[0] = 'FUNC_EXIST';
			  }
			  startImplicitCall(i + 1);
			  return forward(2);
			}
			if (indexOf.call(IMPLICIT_FUNC, tag) >= 0 && this.indexOfTag(i + 1, 'INDENT', null, ':') > -1 && !this.findTagsBackwards(i, ['CLASS', 'EXTENDS', 'IF', 'CATCH', 'SWITCH', 'LEADING_WHEN', 'FOR', 'WHILE', 'UNTIL'])) {
			  startImplicitCall(i + 1);
			  stack.push(['INDENT', i + 2]);
			  return forward(3);
			}
			if (tag === ':') {
			  s = (function() {
				var ref2;
				switch (false) {
				  case ref2 = this.tag(i - 1), indexOf.call(EXPRESSION_END, ref2) < 0:
					return start[1];
				  case this.tag(i - 2) !== '@':
					return i - 2;
				  default:
					return i - 1;
				}
			  }).call(this);
			  while (this.tag(s - 2) === 'HERECOMMENT') {
				s -= 2;
			  }
			  this.insideForDeclaration = nextTag === 'FOR';
			  startsLine = s === 0 || (ref2 = this.tag(s - 1), indexOf.call(LINEBREAKS, ref2) >= 0) || tokens[s - 1].newLine;
			  if (stackTop()) {
				ref3 = stackTop(), stackTag = ref3[0], stackIdx = ref3[1];
				if ((stackTag === '{' || stackTag === 'INDENT' && this.tag(stackIdx - 1) === '{') && (startsLine || this.tag(s - 1) === ',' || this.tag(s - 1) === '{')) {
				  return forward(1);
				}
			  }
			  startImplicitObject(s, !!startsLine);
			  return forward(2);
			}
			if (inImplicitObject() && indexOf.call(LINEBREAKS, tag) >= 0) {
			  stackTop()[2].sameLine = false;
			}
			newLine = prevTag === 'OUTDENT' || prevToken.newLine;
			if (indexOf.call(IMPLICIT_END, tag) >= 0 || indexOf.call(CALL_CLOSERS, tag) >= 0 && newLine) {
			  while (inImplicit()) {
				ref4 = stackTop(), stackTag = ref4[0], stackIdx = ref4[1], (ref5 = ref4[2], sameLine = ref5.sameLine, startsLine = ref5.startsLine);
				if (inImplicitCall() && prevTag !== ',') {
				  endImplicitCall();
				} else if (inImplicitObject() && !this.insideForDeclaration && sameLine && tag !== 'TERMINATOR' && prevTag !== ':') {
				  endImplicitObject();
				} else if (inImplicitObject() && tag === 'TERMINATOR' && prevTag !== ',' && !(startsLine && this.looksObjectish(i + 1))) {
				  if (nextTag === 'HERECOMMENT') {
					return forward(1);
				  }
				  endImplicitObject();
				} else {
				  break;
				}
			  }
			}
			if (tag === ',' && !this.looksObjectish(i + 1) && inImplicitObject() && !this.insideForDeclaration && (nextTag !== 'TERMINATOR' || !this.looksObjectish(i + 2))) {
			  offset = nextTag === 'OUTDENT' ? 1 : 0;
			  while (inImplicitObject()) {
				endImplicitObject(i + offset);
			  }
			}
			return forward(1);
		  });
		};

		Rewriter.prototype.addLocationDataToGeneratedTokens = function() {
		  return this.scanTokens(function(token, i, tokens) {
			var column, line, nextLocation, prevLocation, ref, ref1;
			if (token[2]) {
			  return 1;
			}
			if (!(token.generated || token.explicit)) {
			  return 1;
			}
			if (token[0] === '{' && (nextLocation = (ref = tokens[i + 1]) != null ? ref[2] : void 0)) {
			  line = nextLocation.first_line, column = nextLocation.first_column;
			} else if (prevLocation = (ref1 = tokens[i - 1]) != null ? ref1[2] : void 0) {
			  line = prevLocation.last_line, column = prevLocation.last_column;
			} else {
			  line = column = 0;
			}
			token[2] = {
			  first_line: line,
			  first_column: column,
			  last_line: line,
			  last_column: column
			};
			return 1;
		  });
		};

		Rewriter.prototype.normalizeLines = function() {
		  var action, condition, indent, outdent, starter;
		  starter = indent = outdent = null;
		  condition = function(token, i) {
			var ref, ref1, ref2, ref3;
			return token[1] !== ';' && (ref = token[0], indexOf.call(SINGLE_CLOSERS, ref) >= 0) && !(token[0] === 'TERMINATOR' && (ref1 = this.tag(i + 1), indexOf.call(EXPRESSION_CLOSE, ref1) >= 0)) && !(token[0] === 'ELSE' && starter !== 'THEN') && !(((ref2 = token[0]) === 'CATCH' || ref2 === 'FINALLY') && (starter === '->' || starter === '=>')) || (ref3 = token[0], indexOf.call(CALL_CLOSERS, ref3) >= 0) && this.tokens[i - 1].newLine;
		  };
		  action = function(token, i) {
			return this.tokens.splice((this.tag(i - 1) === ',' ? i - 1 : i), 0, outdent);
		  };
		  return this.scanTokens(function(token, i, tokens) {
			var j, k, ref, ref1, ref2, tag;
			tag = token[0];
			if (tag === 'TERMINATOR') {
			  if (this.tag(i + 1) === 'ELSE' && this.tag(i - 1) !== 'OUTDENT') {
				tokens.splice.apply(tokens, [i, 1].concat(slice.call(this.indentation())));
				return 1;
			  }
			  if (ref = this.tag(i + 1), indexOf.call(EXPRESSION_CLOSE, ref) >= 0) {
				tokens.splice(i, 1);
				return 0;
			  }
			}
			if (tag === 'CATCH') {
			  for (j = k = 1; k <= 2; j = ++k) {
				if (!((ref1 = this.tag(i + j)) === 'OUTDENT' || ref1 === 'TERMINATOR' || ref1 === 'FINALLY')) {
				  continue;
				}
				tokens.splice.apply(tokens, [i + j, 0].concat(slice.call(this.indentation())));
				return 2 + j;
			  }
			}
			if (indexOf.call(SINGLE_LINERS, tag) >= 0 && this.tag(i + 1) !== 'INDENT' && !(tag === 'ELSE' && this.tag(i + 1) === 'IF')) {
			  starter = tag;
			  ref2 = this.indentation(tokens[i]), indent = ref2[0], outdent = ref2[1];
			  if (starter === 'THEN') {
				indent.fromThen = true;
			  }
			  tokens.splice(i + 1, 0, indent);
			  this.detectEnd(i + 2, condition, action);
			  if (tag === 'THEN') {
				tokens.splice(i, 1);
			  }
			  return 1;
			}
			return 1;
		  });
		};

		Rewriter.prototype.tagPostfixConditionals = function() {
		  var action, condition, original;
		  original = null;
		  condition = function(token, i) {
			var prevTag, tag;
			tag = token[0];
			prevTag = this.tokens[i - 1][0];
			return tag === 'TERMINATOR' || (tag === 'INDENT' && indexOf.call(SINGLE_LINERS, prevTag) < 0);
		  };
		  action = function(token, i) {
			if (token[0] !== 'INDENT' || (token.generated && !token.fromThen)) {
			  return original[0] = 'POST_' + original[0];
			}
		  };
		  return this.scanTokens(function(token, i) {
			if (token[0] !== 'IF') {
			  return 1;
			}
			original = token;
			this.detectEnd(i + 1, condition, action);
			return 1;
		  });
		};

		Rewriter.prototype.indentation = function(origin) {
		  var indent, outdent;
		  indent = ['INDENT', 2];
		  outdent = ['OUTDENT', 2];
		  if (origin) {
			indent.generated = outdent.generated = true;
			indent.origin = outdent.origin = origin;
		  } else {
			indent.explicit = outdent.explicit = true;
		  }
		  return [indent, outdent];
		};

		Rewriter.prototype.generate = generate;

		Rewriter.prototype.tag = function(i) {
		  var ref;
		  return (ref = this.tokens[i]) != null ? ref[0] : void 0;
		};

		return Rewriter;

	  })();

	  BALANCED_PAIRS = [['(', ')'], ['[', ']'], ['{', '}'], ['INDENT', 'OUTDENT'], ['CALL_START', 'CALL_END'], ['PARAM_START', 'PARAM_END'], ['INDEX_START', 'INDEX_END'], ['STRING_START', 'STRING_END'], ['REGEX_START', 'REGEX_END']];

	  exports.INVERSES = INVERSES = {};

	  EXPRESSION_START = [];

	  EXPRESSION_END = [];

	  for (k = 0, len = BALANCED_PAIRS.length; k < len; k++) {
		ref = BALANCED_PAIRS[k], left = ref[0], rite = ref[1];
		EXPRESSION_START.push(INVERSES[rite] = left);
		EXPRESSION_END.push(INVERSES[left] = rite);
	  }

	  EXPRESSION_CLOSE = ['CATCH', 'THEN', 'ELSE', 'FINALLY'].concat(EXPRESSION_END);

	  IMPLICIT_FUNC = ['IDENTIFIER', 'SUPER', ')', 'CALL_END', ']', 'INDEX_END', '@', 'THIS'];

	  IMPLICIT_CALL = ['IDENTIFIER', 'NUMBER', 'STRING', 'STRING_START', 'JS', 'REGEX', 'REGEX_START', 'NEW', 'PARAM_START', 'CLASS', 'IF', 'TRY', 'SWITCH', 'THIS', 'BOOL', 'NULL', 'UNDEFINED', 'UNARY', 'YIELD', 'UNARY_MATH', 'SUPER', 'THROW', '@', '->', '=>', '[', '(', '{', '--', '++'];

	  IMPLICIT_UNSPACED_CALL = ['+', '-'];

	  IMPLICIT_END = ['POST_IF', 'FOR', 'WHILE', 'UNTIL', 'WHEN', 'BY', 'LOOP', 'TERMINATOR'];

	  SINGLE_LINERS = ['ELSE', '->', '=>', 'TRY', 'FINALLY', 'THEN'];

	  SINGLE_CLOSERS = ['TERMINATOR', 'CATCH', 'FINALLY', 'ELSE', 'OUTDENT', 'LEADING_WHEN'];

	  LINEBREAKS = ['TERMINATOR', 'INDENT', 'OUTDENT'];

	  CALL_CLOSERS = ['.', '?.', '::', '?::'];
  
	  return exports;
	};
	//#endregion

	//#region URL: /lexer
	modules['/lexer'] = function () {
	  var exports = {};
	  var BOM, BOOL, CALLABLE, CODE, COFFEE_ALIASES, COFFEE_ALIAS_MAP, COFFEE_KEYWORDS, COMMENT, COMPARE, COMPOUND_ASSIGN, HERECOMMENT_ILLEGAL, HEREDOC_DOUBLE, HEREDOC_INDENT, HEREDOC_SINGLE, HEREGEX, HEREGEX_OMIT, IDENTIFIER, INDENTABLE_CLOSERS, INDEXABLE, INVALID_ESCAPE, INVERSES, JSTOKEN, JS_FORBIDDEN, JS_KEYWORDS, LEADING_BLANK_LINE, LINE_BREAK, LINE_CONTINUER, LOGIC, Lexer, MATH, MULTI_DENT, NOT_REGEX, NUMBER, OPERATOR, POSSIBLY_DIVISION, REGEX, REGEX_FLAGS, REGEX_ILLEGAL, RELATION, RESERVED, Rewriter, SHIFT, SIMPLE_STRING_OMIT, STRICT_PROSCRIBED, STRING_DOUBLE, STRING_OMIT, STRING_SINGLE, STRING_START, TRAILING_BLANK_LINE, TRAILING_SPACES, UNARY, UNARY_MATH, VALID_FLAGS, WHITESPACE, compact, count, invertLiterate, key, locationDataToString, ref, ref1, repeat, starts, throwSyntaxError,
		indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

	  ref = require('/rewriter'), Rewriter = ref.Rewriter, INVERSES = ref.INVERSES;

	  ref1 = require('/helpers'), count = ref1.count, starts = ref1.starts, compact = ref1.compact, repeat = ref1.repeat, invertLiterate = ref1.invertLiterate, locationDataToString = ref1.locationDataToString, throwSyntaxError = ref1.throwSyntaxError;

	  exports.Lexer = Lexer = (function() {
		function Lexer() {}

		Lexer.prototype.tokenize = function(code, opts) {
		  var consumed, end, i, ref2;
		  if (opts == null) {
			opts = {};
		  }
		  this.literate = opts.literate;
		  this.indent = 0;
		  this.baseIndent = 0;
		  this.indebt = 0;
		  this.outdebt = 0;
		  this.indents = [];
		  this.ends = [];
		  this.tokens = [];
		  this.chunkLine = opts.line || 0;
		  this.chunkColumn = opts.column || 0;
		  code = this.clean(code);
		  i = 0;
		  while (this.chunk = code.slice(i)) {
			consumed = this.identifierToken() || this.commentToken() || this.whitespaceToken() || this.lineToken() || this.stringToken() || this.numberToken() || this.regexToken() || this.jsToken() || this.literalToken();
			ref2 = this.getLineAndColumnFromChunk(consumed), this.chunkLine = ref2[0], this.chunkColumn = ref2[1];
			i += consumed;
			if (opts.untilBalanced && this.ends.length === 0) {
			  return {
				tokens: this.tokens,
				index: i
			  };
			}
		  }
		  this.closeIndentation();
		  if (end = this.ends.pop()) {
			this.error("missing " + end.tag, end.origin[2]);
		  }
		  if (opts.rewrite === false) {
			return this.tokens;
		  }
		  return (new Rewriter).rewrite(this.tokens);
		};

		Lexer.prototype.clean = function(code) {
		  if (code.charCodeAt(0) === BOM) {
			code = code.slice(1);
		  }
		  code = code.replace(/\r/g, '').replace(TRAILING_SPACES, '');
		  if (WHITESPACE.test(code)) {
			code = "\n" + code;
			this.chunkLine--;
		  }
		  if (this.literate) {
			code = invertLiterate(code);
		  }
		  return code;
		};

		Lexer.prototype.identifierToken = function() {
		  var colon, colonOffset, forcedIdentifier, id, idLength, input, match, poppedToken, prev, ref2, ref3, ref4, ref5, tag, tagToken;
		  if (!(match = IDENTIFIER.exec(this.chunk))) {
			return 0;
		  }
		  input = match[0], id = match[1], colon = match[2];
		  idLength = id.length;
		  poppedToken = void 0;
		  if (id === 'own' && this.tag() === 'FOR') {
			this.token('OWN', id);
			return id.length;
		  }
		  if (id === 'from' && this.tag() === 'YIELD') {
			this.token('FROM', id);
			return id.length;
		  }
		  ref2 = this.tokens, prev = ref2[ref2.length - 1];
		  forcedIdentifier = colon || (prev != null) && (((ref3 = prev[0]) === '.' || ref3 === '?.' || ref3 === '::' || ref3 === '?::') || !prev.spaced && prev[0] === '@');
		  tag = 'IDENTIFIER';
		  if (!forcedIdentifier && (indexOf.call(JS_KEYWORDS, id) >= 0 || indexOf.call(COFFEE_KEYWORDS, id) >= 0)) {
			tag = id.toUpperCase();
			if (tag === 'WHEN' && (ref4 = this.tag(), indexOf.call(LINE_BREAK, ref4) >= 0)) {
			  tag = 'LEADING_WHEN';
			} else if (tag === 'FOR') {
			  this.seenFor = true;
			} else if (tag === 'UNLESS') {
			  tag = 'IF';
			} else if (indexOf.call(UNARY, tag) >= 0) {
			  tag = 'UNARY';
			} else if (indexOf.call(RELATION, tag) >= 0) {
			  if (tag !== 'INSTANCEOF' && this.seenFor) {
				tag = 'FOR' + tag;
				this.seenFor = false;
			  } else {
				tag = 'RELATION';
				if (this.value() === '!') {
				  poppedToken = this.tokens.pop();
				  id = '!' + id;
				}
			  }
			}
		  }
		  if (indexOf.call(JS_FORBIDDEN, id) >= 0) {
			if (forcedIdentifier) {
			  tag = 'IDENTIFIER';
			  id = new String(id);
			  id.reserved = true;
			} else if (indexOf.call(RESERVED, id) >= 0) {
			  this.error("reserved word '" + id + "'", {
				length: id.length
			  });
			}
		  }
		  if (!forcedIdentifier) {
			if (indexOf.call(COFFEE_ALIASES, id) >= 0) {
			  id = COFFEE_ALIAS_MAP[id];
			}
			tag = (function() {
			  switch (id) {
				case '!':
				  return 'UNARY';
				case '==':
				case '!=':
				  return 'COMPARE';
				case '&&':
				case '||':
				  return 'LOGIC';
				case 'true':
				case 'false':
				  return 'BOOL';
				case 'break':
				case 'continue':
				  return 'STATEMENT';
				default:
				  return tag;
			  }
			})();
		  }
		  tagToken = this.token(tag, id, 0, idLength);
		  tagToken.variable = !forcedIdentifier;
		  if (poppedToken) {
			ref5 = [poppedToken[2].first_line, poppedToken[2].first_column], tagToken[2].first_line = ref5[0], tagToken[2].first_column = ref5[1];
		  }
		  if (colon) {
			colonOffset = input.lastIndexOf(':');
			this.token(':', ':', colonOffset, colon.length);
		  }
		  return input.length;
		};

		Lexer.prototype.numberToken = function() {
		  var binaryLiteral, lexedLength, match, number, octalLiteral;
		  if (!(match = NUMBER.exec(this.chunk))) {
			return 0;
		  }
		  number = match[0];
		  lexedLength = number.length;
		  if (/^0[BOX]/.test(number)) {
			this.error("radix prefix in '" + number + "' must be lowercase", {
			  offset: 1
			});
		  } else if (/E/.test(number) && !/^0x/.test(number)) {
			this.error("exponential notation in '" + number + "' must be indicated with a lowercase 'e'", {
			  offset: number.indexOf('E')
			});
		  } else if (/^0\d*[89]/.test(number)) {
			this.error("decimal literal '" + number + "' must not be prefixed with '0'", {
			  length: lexedLength
			});
		  } else if (/^0\d+/.test(number)) {
			this.error("octal literal '" + number + "' must be prefixed with '0o'", {
			  length: lexedLength
			});
		  }
		  if (octalLiteral = /^0o([0-7]+)/.exec(number)) {
			number = '0x' + parseInt(octalLiteral[1], 8).toString(16);
		  }
		  if (binaryLiteral = /^0b([01]+)/.exec(number)) {
			number = '0x' + parseInt(binaryLiteral[1], 2).toString(16);
		  }
		  this.token('NUMBER', number, 0, lexedLength);
		  return lexedLength;
		};

		Lexer.prototype.stringToken = function() {
		  var $, attempt, delimiter, doc, end, heredoc, i, indent, indentRegex, match, quote, ref2, ref3, regex, token, tokens;
		  quote = (STRING_START.exec(this.chunk) || [])[0];
		  if (!quote) {
			return 0;
		  }
		  regex = (function() {
			switch (quote) {
			  case "'":
				return STRING_SINGLE;
			  case '"':
				return STRING_DOUBLE;
			  case "'''":
				return HEREDOC_SINGLE;
			  case '"""':
				return HEREDOC_DOUBLE;
			}
		  })();
		  heredoc = quote.length === 3;
		  ref2 = this.matchWithInterpolations(regex, quote), tokens = ref2.tokens, end = ref2.index;
		  $ = tokens.length - 1;
		  delimiter = quote.charAt(0);
		  if (heredoc) {
			indent = null;
			doc = ((function() {
			  var j, len, results;
			  results = [];
			  for (i = j = 0, len = tokens.length; j < len; i = ++j) {
				token = tokens[i];
				if (token[0] === 'NEOSTRING') {
				  results.push(token[1]);
				}
			  }
			  return results;
			})()).join('#{}');
			while (match = HEREDOC_INDENT.exec(doc)) {
			  attempt = match[1];
			  if (indent === null || (0 < (ref3 = attempt.length) && ref3 < indent.length)) {
				indent = attempt;
			  }
			}
			if (indent) {
			  indentRegex = RegExp("^" + indent, "gm");
			}
			this.mergeInterpolationTokens(tokens, {
			  delimiter: delimiter
			}, (function(_this) {
			  return function(value, i) {
				value = _this.formatString(value);
				if (i === 0) {
				  value = value.replace(LEADING_BLANK_LINE, '');
				}
				if (i === $) {
				  value = value.replace(TRAILING_BLANK_LINE, '');
				}
				if (indentRegex) {
				  value = value.replace(indentRegex, '');
				}
				return value;
			  };
			})(this));
		  } else {
			this.mergeInterpolationTokens(tokens, {
			  delimiter: delimiter
			}, (function(_this) {
			  return function(value, i) {
				value = _this.formatString(value);
				value = value.replace(SIMPLE_STRING_OMIT, function(match, offset) {
				  if ((i === 0 && offset === 0) || (i === $ && offset + match.length === value.length)) {
					return '';
				  } else {
					return ' ';
				  }
				});
				return value;
			  };
			})(this));
		  }
		  return end;
		};

		Lexer.prototype.commentToken = function() {
		  var comment, here, match;
		  if (!(match = this.chunk.match(COMMENT))) {
			return 0;
		  }
		  comment = match[0], here = match[1];
		  if (here) {
			if (match = HERECOMMENT_ILLEGAL.exec(comment)) {
			  this.error("block comments cannot contain " + match[0], {
				offset: match.index,
				length: match[0].length
			  });
			}
			if (here.indexOf('\n') >= 0) {
			  here = here.replace(RegExp("\\n" + (repeat(' ', this.indent)), "g"), '\n');
			}
			this.token('HERECOMMENT', here, 0, comment.length);
		  }
		  return comment.length;
		};

		Lexer.prototype.jsToken = function() {
		  var match, script;
		  if (!(this.chunk.charAt(0) === '`' && (match = JSTOKEN.exec(this.chunk)))) {
			return 0;
		  }
		  this.token('JS', (script = match[0]).slice(1, -1), 0, script.length);
		  return script.length;
		};

		Lexer.prototype.regexToken = function() {
		  var body, closed, end, flags, index, match, origin, prev, ref2, ref3, ref4, regex, tokens;
		  switch (false) {
			case !(match = REGEX_ILLEGAL.exec(this.chunk)):
			  this.error("regular expressions cannot begin with " + match[2], {
				offset: match.index + match[1].length
			  });
			  break;
			case !(match = this.matchWithInterpolations(HEREGEX, '///')):
			  tokens = match.tokens, index = match.index;
			  break;
			case !(match = REGEX.exec(this.chunk)):
			  regex = match[0], body = match[1], closed = match[2];
			  this.validateEscapes(body, {
				isRegex: true,
				offsetInChunk: 1
			  });
			  index = regex.length;
			  ref2 = this.tokens, prev = ref2[ref2.length - 1];
			  if (prev) {
				if (prev.spaced && (ref3 = prev[0], indexOf.call(CALLABLE, ref3) >= 0)) {
				  if (!closed || POSSIBLY_DIVISION.test(regex)) {
					return 0;
				  }
				} else if (ref4 = prev[0], indexOf.call(NOT_REGEX, ref4) >= 0) {
				  return 0;
				}
			  }
			  if (!closed) {
				this.error('missing / (unclosed regex)');
			  }
			  break;
			default:
			  return 0;
		  }
		  flags = REGEX_FLAGS.exec(this.chunk.slice(index))[0];
		  end = index + flags.length;
		  origin = this.makeToken('REGEX', null, 0, end);
		  switch (false) {
			case !!VALID_FLAGS.test(flags):
			  this.error("invalid regular expression flags " + flags, {
				offset: index,
				length: flags.length
			  });
			  break;
			case !(regex || tokens.length === 1):
			  if (body == null) {
				body = this.formatHeregex(tokens[0][1]);
			  }
			  this.token('REGEX', "" + (this.makeDelimitedLiteral(body, {
				delimiter: '/'
			  })) + flags, 0, end, origin);
			  break;
			default:
			  this.token('REGEX_START', '(', 0, 0, origin);
			  this.token('IDENTIFIER', 'RegExp', 0, 0);
			  this.token('CALL_START', '(', 0, 0);
			  this.mergeInterpolationTokens(tokens, {
				delimiter: '"',
				double: true
			  }, this.formatHeregex);
			  if (flags) {
				this.token(',', ',', index, 0);
				this.token('STRING', '"' + flags + '"', index, flags.length);
			  }
			  this.token(')', ')', end, 0);
			  this.token('REGEX_END', ')', end, 0);
		  }
		  return end;
		};

		Lexer.prototype.lineToken = function() {
		  var diff, indent, match, noNewlines, size;
		  if (!(match = MULTI_DENT.exec(this.chunk))) {
			return 0;
		  }
		  indent = match[0];
		  this.seenFor = false;
		  size = indent.length - 1 - indent.lastIndexOf('\n');
		  noNewlines = this.unfinished();
		  if (size - this.indebt === this.indent) {
			if (noNewlines) {
			  this.suppressNewlines();
			} else {
			  this.newlineToken(0);
			}
			return indent.length;
		  }
		  if (size > this.indent) {
			if (noNewlines) {
			  this.indebt = size - this.indent;
			  this.suppressNewlines();
			  return indent.length;
			}
			if (!this.tokens.length) {
			  this.baseIndent = this.indent = size;
			  return indent.length;
			}
			diff = size - this.indent + this.outdebt;
			this.token('INDENT', diff, indent.length - size, size);
			this.indents.push(diff);
			this.ends.push({
			  tag: 'OUTDENT'
			});
			this.outdebt = this.indebt = 0;
			this.indent = size;
		  } else if (size < this.baseIndent) {
			this.error('missing indentation', {
			  offset: indent.length
			});
		  } else {
			this.indebt = 0;
			this.outdentToken(this.indent - size, noNewlines, indent.length);
		  }
		  return indent.length;
		};

		Lexer.prototype.outdentToken = function(moveOut, noNewlines, outdentLength) {
		  var decreasedIndent, dent, lastIndent, ref2;
		  decreasedIndent = this.indent - moveOut;
		  while (moveOut > 0) {
			lastIndent = this.indents[this.indents.length - 1];
			if (!lastIndent) {
			  moveOut = 0;
			} else if (lastIndent === this.outdebt) {
			  moveOut -= this.outdebt;
			  this.outdebt = 0;
			} else if (lastIndent < this.outdebt) {
			  this.outdebt -= lastIndent;
			  moveOut -= lastIndent;
			} else {
			  dent = this.indents.pop() + this.outdebt;
			  if (outdentLength && (ref2 = this.chunk[outdentLength], indexOf.call(INDENTABLE_CLOSERS, ref2) >= 0)) {
				decreasedIndent -= dent - moveOut;
				moveOut = dent;
			  }
			  this.outdebt = 0;
			  this.pair('OUTDENT');
			  this.token('OUTDENT', moveOut, 0, outdentLength);
			  moveOut -= dent;
			}
		  }
		  if (dent) {
			this.outdebt -= moveOut;
		  }
		  while (this.value() === ';') {
			this.tokens.pop();
		  }
		  if (!(this.tag() === 'TERMINATOR' || noNewlines)) {
			this.token('TERMINATOR', '\n', outdentLength, 0);
		  }
		  this.indent = decreasedIndent;
		  return this;
		};

		Lexer.prototype.whitespaceToken = function() {
		  var match, nline, prev, ref2;
		  if (!((match = WHITESPACE.exec(this.chunk)) || (nline = this.chunk.charAt(0) === '\n'))) {
			return 0;
		  }
		  ref2 = this.tokens, prev = ref2[ref2.length - 1];
		  if (prev) {
			prev[match ? 'spaced' : 'newLine'] = true;
		  }
		  if (match) {
			return match[0].length;
		  } else {
			return 0;
		  }
		};

		Lexer.prototype.newlineToken = function(offset) {
		  while (this.value() === ';') {
			this.tokens.pop();
		  }
		  if (this.tag() !== 'TERMINATOR') {
			this.token('TERMINATOR', '\n', offset, 0);
		  }
		  return this;
		};

		Lexer.prototype.suppressNewlines = function() {
		  if (this.value() === '\\') {
			this.tokens.pop();
		  }
		  return this;
		};

		Lexer.prototype.literalToken = function() {
		  var match, prev, ref2, ref3, ref4, ref5, ref6, tag, token, value;
		  if (match = OPERATOR.exec(this.chunk)) {
			value = match[0];
			if (CODE.test(value)) {
			  this.tagParameters();
			}
		  } else {
			value = this.chunk.charAt(0);
		  }
		  tag = value;
		  ref2 = this.tokens, prev = ref2[ref2.length - 1];
		  if (value === '=' && prev) {
			if (!prev[1].reserved && (ref3 = prev[1], indexOf.call(JS_FORBIDDEN, ref3) >= 0)) {
			  this.error("reserved word '" + prev[1] + "' can't be assigned", prev[2]);
			}
			if ((ref4 = prev[1]) === '||' || ref4 === '&&') {
			  prev[0] = 'COMPOUND_ASSIGN';
			  prev[1] += '=';
			  return value.length;
			}
		  }
		  if (value === ';') {
			this.seenFor = false;
			tag = 'TERMINATOR';
		  } else if (indexOf.call(MATH, value) >= 0) {
			tag = 'MATH';
		  } else if (indexOf.call(COMPARE, value) >= 0) {
			tag = 'COMPARE';
		  } else if (indexOf.call(COMPOUND_ASSIGN, value) >= 0) {
			tag = 'COMPOUND_ASSIGN';
		  } else if (indexOf.call(UNARY, value) >= 0) {
			tag = 'UNARY';
		  } else if (indexOf.call(UNARY_MATH, value) >= 0) {
			tag = 'UNARY_MATH';
		  } else if (indexOf.call(SHIFT, value) >= 0) {
			tag = 'SHIFT';
		  } else if (indexOf.call(LOGIC, value) >= 0 || value === '?' && (prev != null ? prev.spaced : void 0)) {
			tag = 'LOGIC';
		  } else if (prev && !prev.spaced) {
			if (value === '(' && (ref5 = prev[0], indexOf.call(CALLABLE, ref5) >= 0)) {
			  if (prev[0] === '?') {
				prev[0] = 'FUNC_EXIST';
			  }
			  tag = 'CALL_START';
			} else if (value === '[' && (ref6 = prev[0], indexOf.call(INDEXABLE, ref6) >= 0)) {
			  tag = 'INDEX_START';
			  switch (prev[0]) {
				case '?':
				  prev[0] = 'INDEX_SOAK';
			  }
			}
		  }
		  token = this.makeToken(tag, value);
		  switch (value) {
			case '(':
			case '{':
			case '[':
			  this.ends.push({
				tag: INVERSES[value],
				origin: token
			  });
			  break;
			case ')':
			case '}':
			case ']':
			  this.pair(value);
		  }
		  this.tokens.push(token);
		  return value.length;
		};

		Lexer.prototype.tagParameters = function() {
		  var i, stack, tok, tokens;
		  if (this.tag() !== ')') {
			return this;
		  }
		  stack = [];
		  tokens = this.tokens;
		  i = tokens.length;
		  tokens[--i][0] = 'PARAM_END';
		  while (tok = tokens[--i]) {
			switch (tok[0]) {
			  case ')':
				stack.push(tok);
				break;
			  case '(':
			  case 'CALL_START':
				if (stack.length) {
				  stack.pop();
				} else if (tok[0] === '(') {
				  tok[0] = 'PARAM_START';
				  return this;
				} else {
				  return this;
				}
			}
		  }
		  return this;
		};

		Lexer.prototype.closeIndentation = function() {
		  return this.outdentToken(this.indent);
		};

		Lexer.prototype.matchWithInterpolations = function(regex, delimiter) {
		  var close, column, firstToken, index, lastToken, line, nested, offsetInChunk, open, ref2, ref3, ref4, str, strPart, tokens;
		  tokens = [];
		  offsetInChunk = delimiter.length;
		  if (this.chunk.slice(0, offsetInChunk) !== delimiter) {
			return null;
		  }
		  str = this.chunk.slice(offsetInChunk);
		  while (true) {
			strPart = regex.exec(str)[0];
			this.validateEscapes(strPart, {
			  isRegex: delimiter.charAt(0) === '/',
			  offsetInChunk: offsetInChunk
			});
			tokens.push(this.makeToken('NEOSTRING', strPart, offsetInChunk));
			str = str.slice(strPart.length);
			offsetInChunk += strPart.length;
			if (str.slice(0, 2) !== '#{') {
			  break;
			}
			ref2 = this.getLineAndColumnFromChunk(offsetInChunk + 1), line = ref2[0], column = ref2[1];
			ref3 = new Lexer().tokenize(str.slice(1), {
			  line: line,
			  column: column,
			  untilBalanced: true
			}), nested = ref3.tokens, index = ref3.index;
			index += 1;
			open = nested[0], close = nested[nested.length - 1];
			open[0] = open[1] = '(';
			close[0] = close[1] = ')';
			close.origin = ['', 'end of interpolation', close[2]];
			if (((ref4 = nested[1]) != null ? ref4[0] : void 0) === 'TERMINATOR') {
			  nested.splice(1, 1);
			}
			tokens.push(['TOKENS', nested]);
			str = str.slice(index);
			offsetInChunk += index;
		  }
		  if (str.slice(0, delimiter.length) !== delimiter) {
			this.error("missing " + delimiter, {
			  length: delimiter.length
			});
		  }
		  firstToken = tokens[0], lastToken = tokens[tokens.length - 1];
		  firstToken[2].first_column -= delimiter.length;
		  lastToken[2].last_column += delimiter.length;
		  if (lastToken[1].length === 0) {
			lastToken[2].last_column -= 1;
		  }
		  return {
			tokens: tokens,
			index: offsetInChunk + delimiter.length
		  };
		};

		Lexer.prototype.mergeInterpolationTokens = function(tokens, options, fn) {
		  var converted, firstEmptyStringIndex, firstIndex, i, j, lastToken, len, locationToken, lparen, plusToken, ref2, rparen, tag, token, tokensToPush, value;
		  if (tokens.length > 1) {
			lparen = this.token('STRING_START', '(', 0, 0);
		  }
		  firstIndex = this.tokens.length;
		  for (i = j = 0, len = tokens.length; j < len; i = ++j) {
			token = tokens[i];
			tag = token[0], value = token[1];
			switch (tag) {
			  case 'TOKENS':
				if (value.length === 2) {
				  continue;
				}
				locationToken = value[0];
				tokensToPush = value;
				break;
			  case 'NEOSTRING':
				converted = fn(token[1], i);
				if (converted.length === 0) {
				  if (i === 0) {
					firstEmptyStringIndex = this.tokens.length;
				  } else {
					continue;
				  }
				}
				if (i === 2 && (firstEmptyStringIndex != null)) {
				  this.tokens.splice(firstEmptyStringIndex, 2);
				}
				token[0] = 'STRING';
				token[1] = this.makeDelimitedLiteral(converted, options);
				locationToken = token;
				tokensToPush = [token];
			}
			if (this.tokens.length > firstIndex) {
			  plusToken = this.token('+', '+');
			  plusToken[2] = {
				first_line: locationToken[2].first_line,
				first_column: locationToken[2].first_column,
				last_line: locationToken[2].first_line,
				last_column: locationToken[2].first_column
			  };
			}
			(ref2 = this.tokens).push.apply(ref2, tokensToPush);
		  }
		  if (lparen) {
			lastToken = tokens[tokens.length - 1];
			lparen.origin = [
			  'STRING', null, {
				first_line: lparen[2].first_line,
				first_column: lparen[2].first_column,
				last_line: lastToken[2].last_line,
				last_column: lastToken[2].last_column
			  }
			];
			rparen = this.token('STRING_END', ')');
			return rparen[2] = {
			  first_line: lastToken[2].last_line,
			  first_column: lastToken[2].last_column,
			  last_line: lastToken[2].last_line,
			  last_column: lastToken[2].last_column
			};
		  }
		};

		Lexer.prototype.pair = function(tag) {
		  var lastIndent, prev, ref2, ref3, wanted;
		  ref2 = this.ends, prev = ref2[ref2.length - 1];
		  if (tag !== (wanted = prev != null ? prev.tag : void 0)) {
			if ('OUTDENT' !== wanted) {
			  this.error("unmatched " + tag);
			}
			ref3 = this.indents, lastIndent = ref3[ref3.length - 1];
			this.outdentToken(lastIndent, true);
			return this.pair(tag);
		  }
		  return this.ends.pop();
		};

		Lexer.prototype.getLineAndColumnFromChunk = function(offset) {
		  var column, lastLine, lineCount, ref2, string;
		  if (offset === 0) {
			return [this.chunkLine, this.chunkColumn];
		  }
		  if (offset >= this.chunk.length) {
			string = this.chunk;
		  } else {
			string = this.chunk.slice(0, +(offset - 1) + 1 || 9e9);
		  }
		  lineCount = count(string, '\n');
		  column = this.chunkColumn;
		  if (lineCount > 0) {
			ref2 = string.split('\n'), lastLine = ref2[ref2.length - 1];
			column = lastLine.length;
		  } else {
			column += string.length;
		  }
		  return [this.chunkLine + lineCount, column];
		};

		Lexer.prototype.makeToken = function(tag, value, offsetInChunk, length) {
		  var lastCharacter, locationData, ref2, ref3, token;
		  if (offsetInChunk == null) {
			offsetInChunk = 0;
		  }
		  if (length == null) {
			length = value.length;
		  }
		  locationData = {};
		  ref2 = this.getLineAndColumnFromChunk(offsetInChunk), locationData.first_line = ref2[0], locationData.first_column = ref2[1];
		  lastCharacter = Math.max(0, length - 1);
		  ref3 = this.getLineAndColumnFromChunk(offsetInChunk + lastCharacter), locationData.last_line = ref3[0], locationData.last_column = ref3[1];
		  token = [tag, value, locationData];
		  return token;
		};

		Lexer.prototype.token = function(tag, value, offsetInChunk, length, origin) {
		  var token;
		  token = this.makeToken(tag, value, offsetInChunk, length);
		  if (origin) {
			token.origin = origin;
		  }
		  this.tokens.push(token);
		  return token;
		};

		Lexer.prototype.tag = function() {
		  var ref2, token;
		  ref2 = this.tokens, token = ref2[ref2.length - 1];
		  return token != null ? token[0] : void 0;
		};

		Lexer.prototype.value = function() {
		  var ref2, token;
		  ref2 = this.tokens, token = ref2[ref2.length - 1];
		  return token != null ? token[1] : void 0;
		};

		Lexer.prototype.unfinished = function() {
		  var ref2;
		  return LINE_CONTINUER.test(this.chunk) || ((ref2 = this.tag()) === '\\' || ref2 === '.' || ref2 === '?.' || ref2 === '?::' || ref2 === 'UNARY' || ref2 === 'MATH' || ref2 === 'UNARY_MATH' || ref2 === '+' || ref2 === '-' || ref2 === 'YIELD' || ref2 === '**' || ref2 === 'SHIFT' || ref2 === 'RELATION' || ref2 === 'COMPARE' || ref2 === 'LOGIC' || ref2 === 'THROW' || ref2 === 'EXTENDS');
		};

		Lexer.prototype.formatString = function(str) {
		  return str.replace(STRING_OMIT, '$1');
		};

		Lexer.prototype.formatHeregex = function(str) {
		  return str.replace(HEREGEX_OMIT, '$1$2');
		};

		Lexer.prototype.validateEscapes = function(str, options) {
		  var before, hex, invalidEscape, match, message, octal, ref2, unicode;
		  if (options == null) {
			options = {};
		  }
		  match = INVALID_ESCAPE.exec(str);
		  if (!match) {
			return;
		  }
		  match[0], before = match[1], octal = match[2], hex = match[3], unicode = match[4];
		  if (options.isRegex && octal && octal.charAt(0) !== '0') {
			return;
		  }
		  message = octal ? "octal escape sequences are not allowed" : "invalid escape sequence";
		  invalidEscape = "\\" + (octal || hex || unicode);
		  return this.error(message + " " + invalidEscape, {
			offset: ((ref2 = options.offsetInChunk) != null ? ref2 : 0) + match.index + before.length,
			length: invalidEscape.length
		  });
		};

		Lexer.prototype.makeDelimitedLiteral = function(body, options) {
		  var regex;
		  if (options == null) {
			options = {};
		  }
		  if (body === '' && options.delimiter === '/') {
			body = '(?:)';
		  }
		  regex = RegExp("(\\\\\\\\)|(\\\\0(?=[1-7]))|\\\\?(" + options.delimiter + ")|\\\\?(?:(\\n)|(\\r)|(\\u2028)|(\\u2029))|(\\\\.)", "g");
		  body = body.replace(regex, function(match, backslash, nul, delimiter, lf, cr, ls, ps, other) {
			switch (false) {
			  case !backslash:
				if (options.double) {
				  return backslash + backslash;
				} else {
				  return backslash;
				}
			  case !nul:
				return '\\x00';
			  case !delimiter:
				return "\\" + delimiter;
			  case !lf:
				return '\\n';
			  case !cr:
				return '\\r';
			  case !ls:
				return '\\u2028';
			  case !ps:
				return '\\u2029';
			  case !other:
				if (options.double) {
				  return "\\" + other;
				} else {
				  return other;
				}
			}
		  });
		  return "" + options.delimiter + body + options.delimiter;
		};

		Lexer.prototype.error = function(message, options) {
		  var first_column, first_line, location, ref2, ref3, ref4;
		  if (options == null) {
			options = {};
		  }
		  location = 'first_line' in options ? options : ((ref3 = this.getLineAndColumnFromChunk((ref2 = options.offset) != null ? ref2 : 0), first_line = ref3[0], first_column = ref3[1], ref3), {
			first_line: first_line,
			first_column: first_column,
			last_column: first_column + ((ref4 = options.length) != null ? ref4 : 1) - 1
		  });
		  return throwSyntaxError(message, location);
		};

		return Lexer;

	  })();

	  JS_KEYWORDS = ['true', 'false', 'null', 'this', 'new', 'delete', 'typeof', 'in', 'instanceof', 'return', 'throw', 'break', 'continue', 'debugger', 'yield', 'if', 'else', 'switch', 'for', 'while', 'do', 'try', 'catch', 'finally', 'class', 'extends', 'super'];

	  COFFEE_KEYWORDS = ['undefined', 'then', 'unless', 'until', 'loop', 'of', 'by', 'when'];

	  COFFEE_ALIAS_MAP = {
		and: '&&',
		or: '||',
		is: '==',
		isnt: '!=',
		not: '!',
		yes: 'true',
		no: 'false',
		on: 'true',
		off: 'false'
	  };

	  COFFEE_ALIASES = (function() {
		var results;
		results = [];
		for (key in COFFEE_ALIAS_MAP) {
		  results.push(key);
		}
		return results;
	  })();

	  COFFEE_KEYWORDS = COFFEE_KEYWORDS.concat(COFFEE_ALIASES);

	  RESERVED = ['case', 'default', 'function', 'var', 'void', 'with', 'const', 'let', 'enum', 'export', 'import', 'native', 'implements', 'interface', 'package', 'private', 'protected', 'public', 'static'];

	  STRICT_PROSCRIBED = ['arguments', 'eval', 'yield*'];

	  JS_FORBIDDEN = JS_KEYWORDS.concat(RESERVED).concat(STRICT_PROSCRIBED);

	  exports.RESERVED = RESERVED.concat(JS_KEYWORDS).concat(COFFEE_KEYWORDS).concat(STRICT_PROSCRIBED);

	  exports.STRICT_PROSCRIBED = STRICT_PROSCRIBED;

	  BOM = 65279;

	  IDENTIFIER = /^(?!\d)((?:(?!\s)[$\w\x7f-\uffff])+)([^\n\S]*:(?!:))?/;

	  NUMBER = /^0b[01]+|^0o[0-7]+|^0x[\da-f]+|^\d*\.?\d+(?:e[+-]?\d+)?/i;

	  OPERATOR = /^(?:[-=]>|[-+*\/%<>&|^!?=]=|>>>=?|([-+:])\1|([&|<>*\/%])\2=?|\?(\.|::)|\.{2,3})/;

	  WHITESPACE = /^[^\n\S]+/;

	  COMMENT = /^###([^#][\s\S]*?)(?:###[^\n\S]*|###$)|^(?:\s*#(?!##[^#]).*)+/;

	  CODE = /^[-=]>/;

	  MULTI_DENT = /^(?:\n[^\n\S]*)+/;

	  JSTOKEN = /^`[^\\`]*(?:\\.[^\\`]*)*`/;

	  STRING_START = /^(?:'''|"""|'|")/;

	  STRING_SINGLE = /^(?:[^\\']|\\[\s\S])*/;

	  STRING_DOUBLE = /^(?:[^\\"#]|\\[\s\S]|\#(?!\{))*/;

	  HEREDOC_SINGLE = /^(?:[^\\']|\\[\s\S]|'(?!''))*/;

	  HEREDOC_DOUBLE = /^(?:[^\\"#]|\\[\s\S]|"(?!"")|\#(?!\{))*/;

	  STRING_OMIT = /((?:\\\\)+)|\\[^\S\n]*\n\s*/g;

	  SIMPLE_STRING_OMIT = /\s*\n\s*/g;

	  HEREDOC_INDENT = /\n+([^\n\S]*)(?=\S)/g;

	  REGEX = /^\/(?!\/)((?:[^[\/\n\\]|\\[^\n]|\[(?:\\[^\n]|[^\]\n\\])*\])*)(\/)?/;

	  REGEX_FLAGS = /^\w*/;

	  VALID_FLAGS = /^(?!.*(.).*\1)[imgy]*$/;

	  HEREGEX = /^(?:[^\\\/#]|\\[\s\S]|\/(?!\/\/)|\#(?!\{))*/;

	  HEREGEX_OMIT = /((?:\\\\)+)|\\(\s)|\s+(?:#.*)?/g;

	  REGEX_ILLEGAL = /^(\/|\/{3}\s*)(\*)/;

	  POSSIBLY_DIVISION = /^\/=?\s/;

	  HERECOMMENT_ILLEGAL = /\*\//;

	  LINE_CONTINUER = /^\s*(?:,|\??\.(?![.\d])|::)/;

	  INVALID_ESCAPE = /((?:^|[^\\])(?:\\\\)*)\\(?:(0[0-7]|[1-7])|(x(?![\da-fA-F]{2}).{0,2})|(u(?![\da-fA-F]{4}).{0,4}))/;

	  LEADING_BLANK_LINE = /^[^\n\S]*\n/;

	  TRAILING_BLANK_LINE = /\n[^\n\S]*$/;

	  TRAILING_SPACES = /\s+$/;

	  COMPOUND_ASSIGN = ['-=', '+=', '/=', '*=', '%=', '||=', '&&=', '?=', '<<=', '>>=', '>>>=', '&=', '^=', '|=', '**=', '//=', '%%='];

	  UNARY = ['NEW', 'TYPEOF', 'DELETE', 'DO'];

	  UNARY_MATH = ['!', '~'];

	  LOGIC = ['&&', '||', '&', '|', '^'];

	  SHIFT = ['<<', '>>', '>>>'];

	  COMPARE = ['==', '!=', '<', '>', '<=', '>='];

	  MATH = ['*', '/', '%', '//', '%%'];

	  RELATION = ['IN', 'OF', 'INSTANCEOF'];

	  BOOL = ['TRUE', 'FALSE'];

	  CALLABLE = ['IDENTIFIER', ')', ']', '?', '@', 'THIS', 'SUPER'];

	  INDEXABLE = CALLABLE.concat(['NUMBER', 'STRING', 'STRING_END', 'REGEX', 'REGEX_END', 'BOOL', 'NULL', 'UNDEFINED', '}', '::']);

	  NOT_REGEX = INDEXABLE.concat(['++', '--']);

	  LINE_BREAK = ['INDENT', 'OUTDENT', 'TERMINATOR'];

	  INDENTABLE_CLOSERS = [')', '}', ']'];

	  return exports;
	};
	//#endregion

	//#region URL: /parser
	modules['/parser'] = function(){
		var exports = {};
		/* parser generated by jison 0.4.15 */
		/*
		  Returns a Parser object of the following structure:

		  Parser: {
			yy: {}
		  }

		  Parser.prototype: {
			yy: {},
			trace: function(),
			symbols_: {associative list: name ==> number},
			terminals_: {associative list: number ==> name},
			productions_: [...],
			performAction: function anonymous(yytext, yyleng, yylineno, yy, yystate, $$, _$),
			table: [...],
			defaultActions: {...},
			parseError: function(str, hash),
			parse: function(input),

			lexer: {
				EOF: 1,
				parseError: function(str, hash),
				setInput: function(input),
				input: function(),
				unput: function(str),
				more: function(),
				less: function(n),
				pastInput: function(),
				upcomingInput: function(),
				showPosition: function(),
				test_match: function(regex_match_array, rule_index),
				next: function(),
				lex: function(),
				begin: function(condition),
				popState: function(),
				_currentRules: function(),
				topState: function(),
				pushState: function(condition),

				options: {
					ranges: boolean           (optional: true ==> token location info will include a .range[] member)
					flex: boolean             (optional: true ==> flex-like lexing behaviour where the rules are tested exhaustively to find the longest match)
					backtrack_lexer: boolean  (optional: true ==> lexer regexes are tested in order and for each matching regex the action code is invoked; the lexer terminates the scan when a token is returned by the action code)
				},

				performAction: function(yy, yy_, $avoiding_name_collisions, YY_START),
				rules: [...],
				conditions: {associative list: name ==> set},
			}
		  }


		  token location info (@$, _$, etc.): {
			first_line: n,
			last_line: n,
			first_column: n,
			last_column: n,
			range: [start_number, end_number]       (where the numbers are indexes into the input string, regular zero-based)
		  }


		  the parseError function receives a 'hash' object with these members for lexer and parser errors: {
			text:        (matched text)
			token:       (the produced terminal token, if any)
			line:        (yylineno)
		  }
		  while parser (grammar) errors will also provide these members, i.e. parser errors deliver a superset of attributes: {
			loc:         (yylloc)
			expected:    (string describing the set of expected tokens)
			recoverable: (boolean: TRUE when the parser has a error recovery rule available for this particular error)
		  }
		*/
		var parser = (function(){
		var o=function(k,v,o,l){for(o=o||{},l=k.length;l--;o[k[l]]=v);return o},$V0=[1,20],$V1=[1,75],$V2=[1,71],$V3=[1,76],$V4=[1,77],$V5=[1,73],$V6=[1,74],$V7=[1,50],$V8=[1,52],$V9=[1,53],$Va=[1,54],$Vb=[1,55],$Vc=[1,45],$Vd=[1,46],$Ve=[1,27],$Vf=[1,60],$Vg=[1,61],$Vh=[1,70],$Vi=[1,43],$Vj=[1,26],$Vk=[1,58],$Vl=[1,59],$Vm=[1,57],$Vn=[1,38],$Vo=[1,44],$Vp=[1,56],$Vq=[1,65],$Vr=[1,66],$Vs=[1,67],$Vt=[1,68],$Vu=[1,42],$Vv=[1,64],$Vw=[1,29],$Vx=[1,30],$Vy=[1,31],$Vz=[1,32],$VA=[1,33],$VB=[1,34],$VC=[1,35],$VD=[1,78],$VE=[1,6,26,34,108],$VF=[1,88],$VG=[1,81],$VH=[1,80],$VI=[1,79],$VJ=[1,82],$VK=[1,83],$VL=[1,84],$VM=[1,85],$VN=[1,86],$VO=[1,87],$VP=[1,91],$VQ=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],$VR=[1,97],$VS=[1,98],$VT=[1,99],$VU=[1,100],$VV=[1,102],$VW=[1,103],$VX=[1,96],$VY=[2,112],$VZ=[1,6,25,26,34,55,60,63,72,73,74,75,77,79,80,84,90,91,92,97,99,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],$V_=[2,79],$V$=[1,108],$V01=[2,58],$V11=[1,112],$V21=[1,117],$V31=[1,118],$V41=[1,120],$V51=[1,6,25,26,34,46,55,60,63,72,73,74,75,77,79,80,84,90,91,92,97,99,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],$V61=[2,76],$V71=[1,6,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],$V81=[1,155],$V91=[1,157],$Va1=[1,152],$Vb1=[1,6,25,26,34,46,55,60,63,72,73,74,75,77,79,80,84,86,90,91,92,97,99,108,110,111,112,116,117,132,135,136,139,140,141,142,143,144,145,146,147,148],$Vc1=[2,95],$Vd1=[1,6,25,26,34,49,55,60,63,72,73,74,75,77,79,80,84,90,91,92,97,99,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],$Ve1=[1,6,25,26,34,46,49,55,60,63,72,73,74,75,77,79,80,84,86,90,91,92,97,99,108,110,111,112,116,117,123,124,132,135,136,139,140,141,142,143,144,145,146,147,148],$Vf1=[1,206],$Vg1=[1,205],$Vh1=[1,6,25,26,34,38,55,60,63,72,73,74,75,77,79,80,84,90,91,92,97,99,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],$Vi1=[2,56],$Vj1=[1,216],$Vk1=[6,25,26,55,60],$Vl1=[6,25,26,46,55,60,63],$Vm1=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,135,136,142,144,145,146,147],$Vn1=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132],$Vo1=[72,73,74,75,77,80,90,91],$Vp1=[1,235],$Vq1=[2,133],$Vr1=[1,6,25,26,34,46,55,60,63,72,73,74,75,77,79,80,84,90,91,92,97,99,108,110,111,112,116,117,123,124,132,135,136,141,142,143,144,145,146,147],$Vs1=[1,244],$Vt1=[6,25,26,60,92,97],$Vu1=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,117,132],$Vv1=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,111,117,132],$Vw1=[123,124],$Vx1=[60,123,124],$Vy1=[1,255],$Vz1=[6,25,26,60,84],$VA1=[6,25,26,49,60,84],$VB1=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,135,136,144,145,146,147],$VC1=[11,28,30,32,33,36,37,40,41,42,43,44,51,52,53,57,58,79,82,85,89,94,95,96,102,106,107,110,112,114,116,125,131,133,134,135,136,137,139,140],$VD1=[2,122],$VE1=[6,25,26],$VF1=[2,57],$VG1=[1,268],$VH1=[1,269],$VI1=[1,6,25,26,34,55,60,63,79,84,92,97,99,104,105,108,110,111,112,116,117,127,129,132,135,136,141,142,143,144,145,146,147],$VJ1=[26,127,129],$VK1=[1,6,26,34,55,60,63,79,84,92,97,99,108,111,117,132],$VL1=[2,71],$VM1=[1,291],$VN1=[1,292],$VO1=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,127,132,135,136,141,142,143,144,145,146,147],$VP1=[1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,112,116,117,132],$VQ1=[1,303],$VR1=[1,304],$VS1=[6,25,26,60],$VT1=[1,6,25,26,34,55,60,63,79,84,92,97,99,104,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],$VU1=[25,60];
		var parser = {trace: function trace() { },
		yy: {},
		symbols_: {"error":2,"Root":3,"Body":4,"Line":5,"TERMINATOR":6,"Expression":7,"Statement":8,"Return":9,"Comment":10,"STATEMENT":11,"Value":12,"Invocation":13,"Code":14,"Operation":15,"Assign":16,"If":17,"Try":18,"While":19,"For":20,"Switch":21,"Class":22,"Throw":23,"Block":24,"INDENT":25,"OUTDENT":26,"Identifier":27,"IDENTIFIER":28,"AlphaNumeric":29,"NUMBER":30,"String":31,"STRING":32,"STRING_START":33,"STRING_END":34,"Regex":35,"REGEX":36,"REGEX_START":37,"REGEX_END":38,"Literal":39,"JS":40,"DEBUGGER":41,"UNDEFINED":42,"NULL":43,"BOOL":44,"Assignable":45,"=":46,"AssignObj":47,"ObjAssignable":48,":":49,"ThisProperty":50,"RETURN":51,"HERECOMMENT":52,"PARAM_START":53,"ParamList":54,"PARAM_END":55,"FuncGlyph":56,"->":57,"=>":58,"OptComma":59,",":60,"Param":61,"ParamVar":62,"...":63,"Array":64,"Object":65,"Splat":66,"SimpleAssignable":67,"Accessor":68,"Parenthetical":69,"Range":70,"This":71,".":72,"?.":73,"::":74,"?::":75,"Index":76,"INDEX_START":77,"IndexValue":78,"INDEX_END":79,"INDEX_SOAK":80,"Slice":81,"{":82,"AssignList":83,"}":84,"CLASS":85,"EXTENDS":86,"OptFuncExist":87,"Arguments":88,"SUPER":89,"FUNC_EXIST":90,"CALL_START":91,"CALL_END":92,"ArgList":93,"THIS":94,"@":95,"[":96,"]":97,"RangeDots":98,"..":99,"Arg":100,"SimpleArgs":101,"TRY":102,"Catch":103,"FINALLY":104,"CATCH":105,"THROW":106,"(":107,")":108,"WhileSource":109,"WHILE":110,"WHEN":111,"UNTIL":112,"Loop":113,"LOOP":114,"ForBody":115,"FOR":116,"BY":117,"ForStart":118,"ForSource":119,"ForVariables":120,"OWN":121,"ForValue":122,"FORIN":123,"FOROF":124,"SWITCH":125,"Whens":126,"ELSE":127,"When":128,"LEADING_WHEN":129,"IfBlock":130,"IF":131,"POST_IF":132,"UNARY":133,"UNARY_MATH":134,"-":135,"+":136,"YIELD":137,"FROM":138,"--":139,"++":140,"?":141,"MATH":142,"**":143,"SHIFT":144,"COMPARE":145,"LOGIC":146,"RELATION":147,"COMPOUND_ASSIGN":148,"$accept":0,"$end":1},
		terminals_: {2:"error",6:"TERMINATOR",11:"STATEMENT",25:"INDENT",26:"OUTDENT",28:"IDENTIFIER",30:"NUMBER",32:"STRING",33:"STRING_START",34:"STRING_END",36:"REGEX",37:"REGEX_START",38:"REGEX_END",40:"JS",41:"DEBUGGER",42:"UNDEFINED",43:"NULL",44:"BOOL",46:"=",49:":",51:"RETURN",52:"HERECOMMENT",53:"PARAM_START",55:"PARAM_END",57:"->",58:"=>",60:",",63:"...",72:".",73:"?.",74:"::",75:"?::",77:"INDEX_START",79:"INDEX_END",80:"INDEX_SOAK",82:"{",84:"}",85:"CLASS",86:"EXTENDS",89:"SUPER",90:"FUNC_EXIST",91:"CALL_START",92:"CALL_END",94:"THIS",95:"@",96:"[",97:"]",99:"..",102:"TRY",104:"FINALLY",105:"CATCH",106:"THROW",107:"(",108:")",110:"WHILE",111:"WHEN",112:"UNTIL",114:"LOOP",116:"FOR",117:"BY",121:"OWN",123:"FORIN",124:"FOROF",125:"SWITCH",127:"ELSE",129:"LEADING_WHEN",131:"IF",132:"POST_IF",133:"UNARY",134:"UNARY_MATH",135:"-",136:"+",137:"YIELD",138:"FROM",139:"--",140:"++",141:"?",142:"MATH",143:"**",144:"SHIFT",145:"COMPARE",146:"LOGIC",147:"RELATION",148:"COMPOUND_ASSIGN"},
		productions_: [0,[3,0],[3,1],[4,1],[4,3],[4,2],[5,1],[5,1],[8,1],[8,1],[8,1],[7,1],[7,1],[7,1],[7,1],[7,1],[7,1],[7,1],[7,1],[7,1],[7,1],[7,1],[7,1],[24,2],[24,3],[27,1],[29,1],[29,1],[31,1],[31,3],[35,1],[35,3],[39,1],[39,1],[39,1],[39,1],[39,1],[39,1],[39,1],[16,3],[16,4],[16,5],[47,1],[47,3],[47,5],[47,1],[48,1],[48,1],[48,1],[9,2],[9,1],[10,1],[14,5],[14,2],[56,1],[56,1],[59,0],[59,1],[54,0],[54,1],[54,3],[54,4],[54,6],[61,1],[61,2],[61,3],[61,1],[62,1],[62,1],[62,1],[62,1],[66,2],[67,1],[67,2],[67,2],[67,1],[45,1],[45,1],[45,1],[12,1],[12,1],[12,1],[12,1],[12,1],[68,2],[68,2],[68,2],[68,2],[68,1],[68,1],[76,3],[76,2],[78,1],[78,1],[65,4],[83,0],[83,1],[83,3],[83,4],[83,6],[22,1],[22,2],[22,3],[22,4],[22,2],[22,3],[22,4],[22,5],[13,3],[13,3],[13,1],[13,2],[87,0],[87,1],[88,2],[88,4],[71,1],[71,1],[50,2],[64,2],[64,4],[98,1],[98,1],[70,5],[81,3],[81,2],[81,2],[81,1],[93,1],[93,3],[93,4],[93,4],[93,6],[100,1],[100,1],[100,1],[101,1],[101,3],[18,2],[18,3],[18,4],[18,5],[103,3],[103,3],[103,2],[23,2],[69,3],[69,5],[109,2],[109,4],[109,2],[109,4],[19,2],[19,2],[19,2],[19,1],[113,2],[113,2],[20,2],[20,2],[20,2],[115,2],[115,4],[115,2],[118,2],[118,3],[122,1],[122,1],[122,1],[122,1],[120,1],[120,3],[119,2],[119,2],[119,4],[119,4],[119,4],[119,6],[119,6],[21,5],[21,7],[21,4],[21,6],[126,1],[126,2],[128,3],[128,4],[130,3],[130,5],[17,1],[17,3],[17,3],[17,3],[15,2],[15,2],[15,2],[15,2],[15,2],[15,2],[15,3],[15,2],[15,2],[15,2],[15,2],[15,2],[15,3],[15,3],[15,3],[15,3],[15,3],[15,3],[15,3],[15,3],[15,3],[15,5],[15,4],[15,3]],
		performAction: function anonymous(yytext, yyleng, yylineno, yy, yystate /* action[1] */, $$ /* vstack */, _$ /* lstack */) {
		/* this == yyval */

		var $0 = $$.length - 1;
		switch (yystate) {
		case 1:
		return this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Block);
		break;
		case 2:
		return this.$ = $$[$0];
		break;
		case 3:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(yy.Block.wrap([$$[$0]]));
		break;
		case 4:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])($$[$0-2].push($$[$0]));
		break;
		case 5:
		this.$ = $$[$0-1];
		break;
		case 6: case 7: case 8: case 9: case 11: case 12: case 13: case 14: case 15: case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 27: case 32: case 34: case 45: case 46: case 47: case 48: case 56: case 57: case 67: case 68: case 69: case 70: case 75: case 76: case 79: case 83: case 89: case 133: case 134: case 136: case 166: case 167: case 183: case 189:
		this.$ = $$[$0];
		break;
		case 10: case 25: case 26: case 28: case 30: case 33: case 35:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Literal($$[$0]));
		break;
		case 23:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Block);
		break;
		case 24: case 31: case 90:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])($$[$0-1]);
		break;
		case 29: case 146:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Parens($$[$0-1]));
		break;
		case 36:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Undefined);
		break;
		case 37:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Null);
		break;
		case 38:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Bool($$[$0]));
		break;
		case 39:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Assign($$[$0-2], $$[$0]));
		break;
		case 40:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Assign($$[$0-3], $$[$0]));
		break;
		case 41:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Assign($$[$0-4], $$[$0-1]));
		break;
		case 42: case 72: case 77: case 78: case 80: case 81: case 82: case 168: case 169:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Value($$[$0]));
		break;
		case 43:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Assign(yy.addLocationDataFn(_$[$0-2])(new yy.Value($$[$0-2])), $$[$0], 'object'));
		break;
		case 44:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Assign(yy.addLocationDataFn(_$[$0-4])(new yy.Value($$[$0-4])), $$[$0-1], 'object'));
		break;
		case 49:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Return($$[$0]));
		break;
		case 50:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Return);
		break;
		case 51:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Comment($$[$0]));
		break;
		case 52:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Code($$[$0-3], $$[$0], $$[$0-1]));
		break;
		case 53:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Code([], $$[$0], $$[$0-1]));
		break;
		case 54:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])('func');
		break;
		case 55:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])('boundfunc');
		break;
		case 58: case 95:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])([]);
		break;
		case 59: case 96: case 128: case 170:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])([$$[$0]]);
		break;
		case 60: case 97: case 129:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])($$[$0-2].concat($$[$0]));
		break;
		case 61: case 98: case 130:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])($$[$0-3].concat($$[$0]));
		break;
		case 62: case 99: case 132:
		this.$ = yy.addLocationDataFn(_$[$0-5], _$[$0])($$[$0-5].concat($$[$0-2]));
		break;
		case 63:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Param($$[$0]));
		break;
		case 64:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Param($$[$0-1], null, true));
		break;
		case 65:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Param($$[$0-2], $$[$0]));
		break;
		case 66: case 135:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Expansion);
		break;
		case 71:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Splat($$[$0-1]));
		break;
		case 73:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])($$[$0-1].add($$[$0]));
		break;
		case 74:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Value($$[$0-1], [].concat($$[$0])));
		break;
		case 84:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Access($$[$0]));
		break;
		case 85:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Access($$[$0], 'soak'));
		break;
		case 86:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])([yy.addLocationDataFn(_$[$0-1])(new yy.Access(new yy.Literal('prototype'))), yy.addLocationDataFn(_$[$0])(new yy.Access($$[$0]))]);
		break;
		case 87:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])([yy.addLocationDataFn(_$[$0-1])(new yy.Access(new yy.Literal('prototype'), 'soak')), yy.addLocationDataFn(_$[$0])(new yy.Access($$[$0]))]);
		break;
		case 88:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Access(new yy.Literal('prototype')));
		break;
		case 91:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(yy.extend($$[$0], {
				  soak: true
				}));
		break;
		case 92:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Index($$[$0]));
		break;
		case 93:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Slice($$[$0]));
		break;
		case 94:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Obj($$[$0-2], $$[$0-3].generated));
		break;
		case 100:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Class);
		break;
		case 101:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Class(null, null, $$[$0]));
		break;
		case 102:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Class(null, $$[$0]));
		break;
		case 103:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Class(null, $$[$0-1], $$[$0]));
		break;
		case 104:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Class($$[$0]));
		break;
		case 105:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Class($$[$0-1], null, $$[$0]));
		break;
		case 106:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Class($$[$0-2], $$[$0]));
		break;
		case 107:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Class($$[$0-3], $$[$0-1], $$[$0]));
		break;
		case 108: case 109:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Call($$[$0-2], $$[$0], $$[$0-1]));
		break;
		case 110:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Call('super', [new yy.Splat(new yy.Literal('arguments'))]));
		break;
		case 111:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Call('super', $$[$0]));
		break;
		case 112:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(false);
		break;
		case 113:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(true);
		break;
		case 114:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])([]);
		break;
		case 115: case 131:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])($$[$0-2]);
		break;
		case 116: case 117:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Value(new yy.Literal('this')));
		break;
		case 118:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Value(yy.addLocationDataFn(_$[$0-1])(new yy.Literal('this')), [yy.addLocationDataFn(_$[$0])(new yy.Access($$[$0]))], 'this'));
		break;
		case 119:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Arr([]));
		break;
		case 120:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Arr($$[$0-2]));
		break;
		case 121:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])('inclusive');
		break;
		case 122:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])('exclusive');
		break;
		case 123:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Range($$[$0-3], $$[$0-1], $$[$0-2]));
		break;
		case 124:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Range($$[$0-2], $$[$0], $$[$0-1]));
		break;
		case 125:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Range($$[$0-1], null, $$[$0]));
		break;
		case 126:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Range(null, $$[$0], $$[$0-1]));
		break;
		case 127:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])(new yy.Range(null, null, $$[$0]));
		break;
		case 137:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])([].concat($$[$0-2], $$[$0]));
		break;
		case 138:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Try($$[$0]));
		break;
		case 139:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Try($$[$0-1], $$[$0][0], $$[$0][1]));
		break;
		case 140:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Try($$[$0-2], null, null, $$[$0]));
		break;
		case 141:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Try($$[$0-3], $$[$0-2][0], $$[$0-2][1], $$[$0]));
		break;
		case 142:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])([$$[$0-1], $$[$0]]);
		break;
		case 143:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])([yy.addLocationDataFn(_$[$0-1])(new yy.Value($$[$0-1])), $$[$0]]);
		break;
		case 144:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])([null, $$[$0]]);
		break;
		case 145:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Throw($$[$0]));
		break;
		case 147:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Parens($$[$0-2]));
		break;
		case 148:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.While($$[$0]));
		break;
		case 149:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.While($$[$0-2], {
				  guard: $$[$0]
				}));
		break;
		case 150:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.While($$[$0], {
				  invert: true
				}));
		break;
		case 151:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.While($$[$0-2], {
				  invert: true,
				  guard: $$[$0]
				}));
		break;
		case 152:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])($$[$0-1].addBody($$[$0]));
		break;
		case 153: case 154:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])($$[$0].addBody(yy.addLocationDataFn(_$[$0-1])(yy.Block.wrap([$$[$0-1]]))));
		break;
		case 155:
		this.$ = yy.addLocationDataFn(_$[$0], _$[$0])($$[$0]);
		break;
		case 156:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.While(yy.addLocationDataFn(_$[$0-1])(new yy.Literal('true'))).addBody($$[$0]));
		break;
		case 157:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.While(yy.addLocationDataFn(_$[$0-1])(new yy.Literal('true'))).addBody(yy.addLocationDataFn(_$[$0])(yy.Block.wrap([$$[$0]]))));
		break;
		case 158: case 159:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.For($$[$0-1], $$[$0]));
		break;
		case 160:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.For($$[$0], $$[$0-1]));
		break;
		case 161:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])({
				  source: yy.addLocationDataFn(_$[$0])(new yy.Value($$[$0]))
				});
		break;
		case 162:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])({
				  source: yy.addLocationDataFn(_$[$0-2])(new yy.Value($$[$0-2])),
				  step: $$[$0]
				});
		break;
		case 163:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])((function () {
				$$[$0].own = $$[$0-1].own;
				$$[$0].name = $$[$0-1][0];
				$$[$0].index = $$[$0-1][1];
				return $$[$0];
			  }()));
		break;
		case 164:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])($$[$0]);
		break;
		case 165:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])((function () {
				$$[$0].own = true;
				return $$[$0];
			  }()));
		break;
		case 171:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])([$$[$0-2], $$[$0]]);
		break;
		case 172:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])({
				  source: $$[$0]
				});
		break;
		case 173:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])({
				  source: $$[$0],
				  object: true
				});
		break;
		case 174:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])({
				  source: $$[$0-2],
				  guard: $$[$0]
				});
		break;
		case 175:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])({
				  source: $$[$0-2],
				  guard: $$[$0],
				  object: true
				});
		break;
		case 176:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])({
				  source: $$[$0-2],
				  step: $$[$0]
				});
		break;
		case 177:
		this.$ = yy.addLocationDataFn(_$[$0-5], _$[$0])({
				  source: $$[$0-4],
				  guard: $$[$0-2],
				  step: $$[$0]
				});
		break;
		case 178:
		this.$ = yy.addLocationDataFn(_$[$0-5], _$[$0])({
				  source: $$[$0-4],
				  step: $$[$0-2],
				  guard: $$[$0]
				});
		break;
		case 179:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Switch($$[$0-3], $$[$0-1]));
		break;
		case 180:
		this.$ = yy.addLocationDataFn(_$[$0-6], _$[$0])(new yy.Switch($$[$0-5], $$[$0-3], $$[$0-1]));
		break;
		case 181:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Switch(null, $$[$0-1]));
		break;
		case 182:
		this.$ = yy.addLocationDataFn(_$[$0-5], _$[$0])(new yy.Switch(null, $$[$0-3], $$[$0-1]));
		break;
		case 184:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])($$[$0-1].concat($$[$0]));
		break;
		case 185:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])([[$$[$0-1], $$[$0]]]);
		break;
		case 186:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])([[$$[$0-2], $$[$0-1]]]);
		break;
		case 187:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.If($$[$0-1], $$[$0], {
				  type: $$[$0-2]
				}));
		break;
		case 188:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])($$[$0-4].addElse(yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.If($$[$0-1], $$[$0], {
				  type: $$[$0-2]
				}))));
		break;
		case 190:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])($$[$0-2].addElse($$[$0]));
		break;
		case 191: case 192:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.If($$[$0], yy.addLocationDataFn(_$[$0-2])(yy.Block.wrap([$$[$0-2]])), {
				  type: $$[$0-1],
				  statement: true
				}));
		break;
		case 193: case 194: case 197: case 198:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Op($$[$0-1], $$[$0]));
		break;
		case 195:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Op('-', $$[$0]));
		break;
		case 196:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Op('+', $$[$0]));
		break;
		case 199:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Op($$[$0-2].concat($$[$0-1]), $$[$0]));
		break;
		case 200:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Op('--', $$[$0]));
		break;
		case 201:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Op('++', $$[$0]));
		break;
		case 202:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Op('--', $$[$0-1], null, true));
		break;
		case 203:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Op('++', $$[$0-1], null, true));
		break;
		case 204:
		this.$ = yy.addLocationDataFn(_$[$0-1], _$[$0])(new yy.Existence($$[$0-1]));
		break;
		case 205:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Op('+', $$[$0-2], $$[$0]));
		break;
		case 206:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Op('-', $$[$0-2], $$[$0]));
		break;
		case 207: case 208: case 209: case 210: case 211:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Op($$[$0-1], $$[$0-2], $$[$0]));
		break;
		case 212:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])((function () {
				if ($$[$0-1].charAt(0) === '!') {
				  return new yy.Op($$[$0-1].slice(1), $$[$0-2], $$[$0]).invert();
				} else {
				  return new yy.Op($$[$0-1], $$[$0-2], $$[$0]);
				}
			  }()));
		break;
		case 213:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Assign($$[$0-2], $$[$0], $$[$0-1]));
		break;
		case 214:
		this.$ = yy.addLocationDataFn(_$[$0-4], _$[$0])(new yy.Assign($$[$0-4], $$[$0-1], $$[$0-3]));
		break;
		case 215:
		this.$ = yy.addLocationDataFn(_$[$0-3], _$[$0])(new yy.Assign($$[$0-3], $$[$0], $$[$0-2]));
		break;
		case 216:
		this.$ = yy.addLocationDataFn(_$[$0-2], _$[$0])(new yy.Extends($$[$0-2], $$[$0]));
		break;
		}
		},
		table: [{1:[2,1],3:1,4:2,5:3,7:4,8:5,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{1:[3]},{1:[2,2],6:$VD},o($VE,[2,3]),o($VE,[2,6],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VE,[2,7],{118:69,109:92,115:93,110:$Vq,112:$Vr,116:$Vt,132:$VP}),o($VQ,[2,11],{87:94,68:95,76:101,72:$VR,73:$VS,74:$VT,75:$VU,77:$VV,80:$VW,90:$VX,91:$VY}),o($VQ,[2,12],{76:101,87:104,68:105,72:$VR,73:$VS,74:$VT,75:$VU,77:$VV,80:$VW,90:$VX,91:$VY}),o($VQ,[2,13]),o($VQ,[2,14]),o($VQ,[2,15]),o($VQ,[2,16]),o($VQ,[2,17]),o($VQ,[2,18]),o($VQ,[2,19]),o($VQ,[2,20]),o($VQ,[2,21]),o($VQ,[2,22]),o($VQ,[2,8]),o($VQ,[2,9]),o($VQ,[2,10]),o($VZ,$V_,{46:[1,106]}),o($VZ,[2,80]),o($VZ,[2,81]),o($VZ,[2,82]),o($VZ,[2,83]),o([1,6,25,26,34,38,55,60,63,72,73,74,75,77,79,80,84,90,92,97,99,108,110,111,112,116,117,132,135,136,141,142,143,144,145,146,147],[2,110],{88:107,91:$V$}),o([6,25,55,60],$V01,{54:109,61:110,62:111,27:113,50:114,64:115,65:116,28:$V1,63:$V11,82:$Vh,95:$V21,96:$V31}),{24:119,25:$V41},{7:121,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:123,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:124,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:125,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:127,8:126,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,138:[1,128],139:$VB,140:$VC},{12:130,13:131,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:132,50:63,64:47,65:48,67:129,69:23,70:24,71:25,82:$Vh,89:$Vj,94:$Vk,95:$Vl,96:$Vm,107:$Vp},{12:130,13:131,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:132,50:63,64:47,65:48,67:133,69:23,70:24,71:25,82:$Vh,89:$Vj,94:$Vk,95:$Vl,96:$Vm,107:$Vp},o($V51,$V61,{86:[1,137],139:[1,134],140:[1,135],148:[1,136]}),o($VQ,[2,189],{127:[1,138]}),{24:139,25:$V41},{24:140,25:$V41},o($VQ,[2,155]),{24:141,25:$V41},{7:142,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:[1,143],27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($V71,[2,100],{39:22,69:23,70:24,71:25,64:47,65:48,29:49,35:51,27:62,50:63,31:72,12:130,13:131,45:132,24:144,67:146,25:$V41,28:$V1,30:$V2,32:$V3,33:$V4,36:$V5,37:$V6,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,82:$Vh,86:[1,145],89:$Vj,94:$Vk,95:$Vl,96:$Vm,107:$Vp}),{7:147,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,141,142,143,144,145,146,147],[2,50],{12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,9:18,10:19,45:21,39:22,69:23,70:24,71:25,56:28,67:36,130:37,109:39,113:40,115:41,64:47,65:48,29:49,35:51,27:62,50:63,118:69,31:72,8:122,7:148,11:$V0,28:$V1,30:$V2,32:$V3,33:$V4,36:$V5,37:$V6,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,51:$Vc,52:$Vd,53:$Ve,57:$Vf,58:$Vg,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,114:$Vs,125:$Vu,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC}),o($VQ,[2,51]),o($V51,[2,77]),o($V51,[2,78]),o($VZ,[2,32]),o($VZ,[2,33]),o($VZ,[2,34]),o($VZ,[2,35]),o($VZ,[2,36]),o($VZ,[2,37]),o($VZ,[2,38]),{4:149,5:3,7:4,8:5,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:[1,150],27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:151,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:$V81,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,63:$V91,64:47,65:48,66:156,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,93:153,94:$Vk,95:$Vl,96:$Vm,97:$Va1,100:154,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VZ,[2,116]),o($VZ,[2,117],{27:158,28:$V1}),{25:[2,54]},{25:[2,55]},o($Vb1,[2,72]),o($Vb1,[2,75]),{7:159,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:160,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:161,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:163,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,24:162,25:$V41,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{27:168,28:$V1,50:169,64:170,65:171,70:164,82:$Vh,95:$V21,96:$Vm,120:165,121:[1,166],122:167},{119:172,123:[1,173],124:[1,174]},o([6,25,60,84],$Vc1,{31:72,83:175,47:176,48:177,10:178,27:179,29:180,50:181,28:$V1,30:$V2,32:$V3,33:$V4,52:$Vd,95:$V21}),o($Vd1,[2,26]),o($Vd1,[2,27]),o($VZ,[2,30]),{12:130,13:182,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:132,50:63,64:47,65:48,67:183,69:23,70:24,71:25,82:$Vh,89:$Vj,94:$Vk,95:$Vl,96:$Vm,107:$Vp},o($Ve1,[2,25]),o($Vd1,[2,28]),{4:184,5:3,7:4,8:5,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VE,[2,5],{7:4,8:5,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,9:18,10:19,45:21,39:22,69:23,70:24,71:25,56:28,67:36,130:37,109:39,113:40,115:41,64:47,65:48,29:49,35:51,27:62,50:63,118:69,31:72,5:185,11:$V0,28:$V1,30:$V2,32:$V3,33:$V4,36:$V5,37:$V6,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,51:$Vc,52:$Vd,53:$Ve,57:$Vf,58:$Vg,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,110:$Vq,112:$Vr,114:$Vs,116:$Vt,125:$Vu,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC}),o($VQ,[2,204]),{7:186,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:187,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:188,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:189,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:190,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:191,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:192,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:193,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:194,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VQ,[2,154]),o($VQ,[2,159]),{7:195,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VQ,[2,153]),o($VQ,[2,158]),{88:196,91:$V$},o($Vb1,[2,73]),{91:[2,113]},{27:197,28:$V1},{27:198,28:$V1},o($Vb1,[2,88],{27:199,28:$V1}),{27:200,28:$V1},o($Vb1,[2,89]),{7:202,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,63:$Vf1,64:47,65:48,67:36,69:23,70:24,71:25,78:201,81:203,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,98:204,99:$Vg1,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{76:207,77:$VV,80:$VW},{88:208,91:$V$},o($Vb1,[2,74]),{6:[1,210],7:209,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:[1,211],27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($Vh1,[2,111]),{7:214,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:$V81,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,63:$V91,64:47,65:48,66:156,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,92:[1,212],93:213,94:$Vk,95:$Vl,96:$Vm,100:154,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o([6,25],$Vi1,{59:217,55:[1,215],60:$Vj1}),o($Vk1,[2,59]),o($Vk1,[2,63],{46:[1,219],63:[1,218]}),o($Vk1,[2,66]),o($Vl1,[2,67]),o($Vl1,[2,68]),o($Vl1,[2,69]),o($Vl1,[2,70]),{27:158,28:$V1},{7:214,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:$V81,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,63:$V91,64:47,65:48,66:156,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,93:153,94:$Vk,95:$Vl,96:$Vm,97:$Va1,100:154,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VQ,[2,53]),{4:221,5:3,7:4,8:5,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,26:[1,220],27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,135,136,142,143,144,145,146,147],[2,193],{118:69,109:89,115:90,141:$VI}),{109:92,110:$Vq,112:$Vr,115:93,116:$Vt,118:69,132:$VP},o($Vm1,[2,194],{118:69,109:89,115:90,141:$VI,143:$VK}),o($Vm1,[2,195],{118:69,109:89,115:90,141:$VI,143:$VK}),o($Vm1,[2,196],{118:69,109:89,115:90,141:$VI,143:$VK}),o($VQ,[2,197],{118:69,109:92,115:93}),o($Vn1,[2,198],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{7:222,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VQ,[2,200],{72:$V61,73:$V61,74:$V61,75:$V61,77:$V61,80:$V61,90:$V61,91:$V61}),{68:95,72:$VR,73:$VS,74:$VT,75:$VU,76:101,77:$VV,80:$VW,87:94,90:$VX,91:$VY},{68:105,72:$VR,73:$VS,74:$VT,75:$VU,76:101,77:$VV,80:$VW,87:104,90:$VX,91:$VY},o($Vo1,$V_),o($VQ,[2,201],{72:$V61,73:$V61,74:$V61,75:$V61,77:$V61,80:$V61,90:$V61,91:$V61}),o($VQ,[2,202]),o($VQ,[2,203]),{6:[1,225],7:223,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:[1,224],27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:226,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{24:227,25:$V41,131:[1,228]},o($VQ,[2,138],{103:229,104:[1,230],105:[1,231]}),o($VQ,[2,152]),o($VQ,[2,160]),{25:[1,232],109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},{126:233,128:234,129:$Vp1},o($VQ,[2,101]),{7:236,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($V71,[2,104],{24:237,25:$V41,72:$V61,73:$V61,74:$V61,75:$V61,77:$V61,80:$V61,90:$V61,91:$V61,86:[1,238]}),o($Vn1,[2,145],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vn1,[2,49],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{6:$VD,108:[1,239]},{4:240,5:3,7:4,8:5,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o([6,25,60,97],$Vq1,{118:69,109:89,115:90,98:241,63:[1,242],99:$Vg1,110:$Vq,112:$Vr,116:$Vt,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vr1,[2,119]),o([6,25,97],$Vi1,{59:243,60:$Vs1}),o($Vt1,[2,128]),{7:214,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:$V81,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,63:$V91,64:47,65:48,66:156,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,93:245,94:$Vk,95:$Vl,96:$Vm,100:154,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($Vt1,[2,134]),o($Vt1,[2,135]),o($Ve1,[2,118]),{24:246,25:$V41,109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},o($Vu1,[2,148],{118:69,109:89,115:90,110:$Vq,111:[1,247],112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vu1,[2,150],{118:69,109:89,115:90,110:$Vq,111:[1,248],112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VQ,[2,156]),o($Vv1,[2,157],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,132,135,136,141,142,143,144,145,146,147],[2,161],{117:[1,249]}),o($Vw1,[2,164]),{27:168,28:$V1,50:169,64:170,65:171,82:$Vh,95:$V21,96:$V31,120:250,122:167},o($Vw1,[2,170],{60:[1,251]}),o($Vx1,[2,166]),o($Vx1,[2,167]),o($Vx1,[2,168]),o($Vx1,[2,169]),o($VQ,[2,163]),{7:252,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:253,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o([6,25,84],$Vi1,{59:254,60:$Vy1}),o($Vz1,[2,96]),o($Vz1,[2,42],{49:[1,256]}),o($Vz1,[2,45]),o($VA1,[2,46]),o($VA1,[2,47]),o($VA1,[2,48]),{38:[1,257],68:105,72:$VR,73:$VS,74:$VT,75:$VU,76:101,77:$VV,80:$VW,87:104,90:$VX,91:$VY},o($Vo1,$V61),{6:$VD,34:[1,258]},o($VE,[2,4]),o($VB1,[2,205],{118:69,109:89,115:90,141:$VI,142:$VJ,143:$VK}),o($VB1,[2,206],{118:69,109:89,115:90,141:$VI,142:$VJ,143:$VK}),o($Vm1,[2,207],{118:69,109:89,115:90,141:$VI,143:$VK}),o($Vm1,[2,208],{118:69,109:89,115:90,141:$VI,143:$VK}),o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,144,145,146,147],[2,209],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK}),o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,145,146],[2,210],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,147:$VO}),o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,146],[2,211],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,147:$VO}),o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,117,132,145,146,147],[2,212],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL}),o($Vv1,[2,192],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vv1,[2,191],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vh1,[2,108]),o($Vb1,[2,84]),o($Vb1,[2,85]),o($Vb1,[2,86]),o($Vb1,[2,87]),{79:[1,259]},{63:$Vf1,79:[2,92],98:260,99:$Vg1,109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},{79:[2,93]},{7:261,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,79:[2,127],82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VC1,[2,121]),o($VC1,$VD1),o($Vb1,[2,91]),o($Vh1,[2,109]),o($Vn1,[2,39],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{7:262,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:263,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($Vh1,[2,114]),o([6,25,92],$Vi1,{59:264,60:$Vs1}),o($Vt1,$Vq1,{118:69,109:89,115:90,63:[1,265],110:$Vq,112:$Vr,116:$Vt,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{56:266,57:$Vf,58:$Vg},o($VE1,$VF1,{62:111,27:113,50:114,64:115,65:116,61:267,28:$V1,63:$V11,82:$Vh,95:$V21,96:$V31}),{6:$VG1,25:$VH1},o($Vk1,[2,64]),{7:270,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VI1,[2,23]),{6:$VD,26:[1,271]},o($Vn1,[2,199],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vn1,[2,213],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{7:272,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:273,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($Vn1,[2,216],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VQ,[2,190]),{7:274,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VQ,[2,139],{104:[1,275]}),{24:276,25:$V41},{24:279,25:$V41,27:277,28:$V1,65:278,82:$Vh},{126:280,128:234,129:$Vp1},{26:[1,281],127:[1,282],128:283,129:$Vp1},o($VJ1,[2,183]),{7:285,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,101:284,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VK1,[2,102],{118:69,109:89,115:90,24:286,25:$V41,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VQ,[2,105]),{7:287,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VZ,[2,146]),{6:$VD,26:[1,288]},{7:289,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o([11,28,30,32,33,36,37,40,41,42,43,44,51,52,53,57,58,82,85,89,94,95,96,102,106,107,110,112,114,116,125,131,133,134,135,136,137,139,140],$VD1,{6:$VL1,25:$VL1,60:$VL1,97:$VL1}),{6:$VM1,25:$VN1,97:[1,290]},o([6,25,26,92,97],$VF1,{12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,9:18,10:19,45:21,39:22,69:23,70:24,71:25,56:28,67:36,130:37,109:39,113:40,115:41,64:47,65:48,29:49,35:51,27:62,50:63,118:69,31:72,8:122,66:156,7:214,100:293,11:$V0,28:$V1,30:$V2,32:$V3,33:$V4,36:$V5,37:$V6,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,51:$Vc,52:$Vd,53:$Ve,57:$Vf,58:$Vg,63:$V91,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,110:$Vq,112:$Vr,114:$Vs,116:$Vt,125:$Vu,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC}),o($VE1,$Vi1,{59:294,60:$Vs1}),o($VO1,[2,187]),{7:295,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:296,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:297,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($Vw1,[2,165]),{27:168,28:$V1,50:169,64:170,65:171,82:$Vh,95:$V21,96:$V31,122:298},o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,112,116,132],[2,172],{118:69,109:89,115:90,111:[1,299],117:[1,300],135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VP1,[2,173],{118:69,109:89,115:90,111:[1,301],135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{6:$VQ1,25:$VR1,84:[1,302]},o([6,25,26,84],$VF1,{31:72,48:177,10:178,27:179,29:180,50:181,47:305,28:$V1,30:$V2,32:$V3,33:$V4,52:$Vd,95:$V21}),{7:306,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:[1,307],27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VZ,[2,31]),o($Vd1,[2,29]),o($Vb1,[2,90]),{7:308,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,79:[2,125],82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{79:[2,126],109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},o($Vn1,[2,40],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{26:[1,309],109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},{6:$VM1,25:$VN1,92:[1,310]},o($Vt1,$VL1),{24:311,25:$V41},o($Vk1,[2,60]),{27:113,28:$V1,50:114,61:312,62:111,63:$V11,64:115,65:116,82:$Vh,95:$V21,96:$V31},o($VS1,$V01,{61:110,62:111,27:113,50:114,64:115,65:116,54:313,28:$V1,63:$V11,82:$Vh,95:$V21,96:$V31}),o($Vk1,[2,65],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VI1,[2,24]),{26:[1,314],109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},o($Vn1,[2,215],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{24:315,25:$V41,109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},{24:316,25:$V41},o($VQ,[2,140]),{24:317,25:$V41},{24:318,25:$V41},o($VT1,[2,144]),{26:[1,319],127:[1,320],128:283,129:$Vp1},o($VQ,[2,181]),{24:321,25:$V41},o($VJ1,[2,184]),{24:322,25:$V41,60:[1,323]},o($VU1,[2,136],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VQ,[2,103]),o($VK1,[2,106],{118:69,109:89,115:90,24:324,25:$V41,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{108:[1,325]},{97:[1,326],109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},o($Vr1,[2,120]),{7:214,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,63:$V91,64:47,65:48,66:156,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,100:327,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:214,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,25:$V81,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,63:$V91,64:47,65:48,66:156,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,93:328,94:$Vk,95:$Vl,96:$Vm,100:154,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($Vt1,[2,129]),{6:$VM1,25:$VN1,26:[1,329]},o($Vv1,[2,149],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vv1,[2,151],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vv1,[2,162],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vw1,[2,171]),{7:330,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:331,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:332,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($Vr1,[2,94]),{10:178,27:179,28:$V1,29:180,30:$V2,31:72,32:$V3,33:$V4,47:333,48:177,50:181,52:$Vd,95:$V21},o($VS1,$Vc1,{31:72,47:176,48:177,10:178,27:179,29:180,50:181,83:334,28:$V1,30:$V2,32:$V3,33:$V4,52:$Vd,95:$V21}),o($Vz1,[2,97]),o($Vz1,[2,43],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{7:335,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{79:[2,124],109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},o($VQ,[2,41]),o($Vh1,[2,115]),o($VQ,[2,52]),o($Vk1,[2,61]),o($VE1,$Vi1,{59:336,60:$Vj1}),o($VQ,[2,214]),o($VO1,[2,188]),o($VQ,[2,141]),o($VT1,[2,142]),o($VT1,[2,143]),o($VQ,[2,179]),{24:337,25:$V41},{26:[1,338]},o($VJ1,[2,185],{6:[1,339]}),{7:340,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},o($VQ,[2,107]),o($VZ,[2,147]),o($VZ,[2,123]),o($Vt1,[2,130]),o($VE1,$Vi1,{59:341,60:$Vs1}),o($Vt1,[2,131]),o([1,6,25,26,34,55,60,63,79,84,92,97,99,108,110,111,112,116,132],[2,174],{118:69,109:89,115:90,117:[1,342],135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($VP1,[2,176],{118:69,109:89,115:90,111:[1,343],135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vn1,[2,175],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vz1,[2,98]),o($VE1,$Vi1,{59:344,60:$Vy1}),{26:[1,345],109:89,110:$Vq,112:$Vr,115:90,116:$Vt,118:69,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO},{6:$VG1,25:$VH1,26:[1,346]},{26:[1,347]},o($VQ,[2,182]),o($VJ1,[2,186]),o($VU1,[2,137],{118:69,109:89,115:90,110:$Vq,112:$Vr,116:$Vt,132:$VF,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),{6:$VM1,25:$VN1,26:[1,348]},{7:349,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{7:350,8:122,9:18,10:19,11:$V0,12:6,13:7,14:8,15:9,16:10,17:11,18:12,19:13,20:14,21:15,22:16,23:17,27:62,28:$V1,29:49,30:$V2,31:72,32:$V3,33:$V4,35:51,36:$V5,37:$V6,39:22,40:$V7,41:$V8,42:$V9,43:$Va,44:$Vb,45:21,50:63,51:$Vc,52:$Vd,53:$Ve,56:28,57:$Vf,58:$Vg,64:47,65:48,67:36,69:23,70:24,71:25,82:$Vh,85:$Vi,89:$Vj,94:$Vk,95:$Vl,96:$Vm,102:$Vn,106:$Vo,107:$Vp,109:39,110:$Vq,112:$Vr,113:40,114:$Vs,115:41,116:$Vt,118:69,125:$Vu,130:37,131:$Vv,133:$Vw,134:$Vx,135:$Vy,136:$Vz,137:$VA,139:$VB,140:$VC},{6:$VQ1,25:$VR1,26:[1,351]},o($Vz1,[2,44]),o($Vk1,[2,62]),o($VQ,[2,180]),o($Vt1,[2,132]),o($Vn1,[2,177],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vn1,[2,178],{118:69,109:89,115:90,135:$VG,136:$VH,141:$VI,142:$VJ,143:$VK,144:$VL,145:$VM,146:$VN,147:$VO}),o($Vz1,[2,99])],
		defaultActions: {60:[2,54],61:[2,55],96:[2,113],203:[2,93]},
		parseError: function parseError(str, hash) {
			if (hash.recoverable) {
				this.trace(str);
			} else {
				throw new Error(str);
			}
		},
		parse: function parse(input) {
			var self = this, stack = [0], tstack = [], vstack = [null], lstack = [], table = this.table, yytext = '', yylineno = 0, yyleng = 0, recovering = 0, TERROR = 2, EOF = 1;
			var args = lstack.slice.call(arguments, 1);
			var lexer = Object.create(this.lexer);
			var sharedState = { yy: {} };
			for (var k in this.yy) {
				if (Object.prototype.hasOwnProperty.call(this.yy, k)) {
					sharedState.yy[k] = this.yy[k];
				}
			}
			lexer.setInput(input, sharedState.yy);
			sharedState.yy.lexer = lexer;
			sharedState.yy.parser = this;
			if (typeof lexer.yylloc == 'undefined') {
				lexer.yylloc = {};
			}
			var yyloc = lexer.yylloc;
			lstack.push(yyloc);
			var ranges = lexer.options && lexer.options.ranges;
			if (typeof sharedState.yy.parseError === 'function') {
				this.parseError = sharedState.yy.parseError;
			} else {
				this.parseError = Object.getPrototypeOf(this).parseError;
			}
			function popStack(n) {
				stack.length = stack.length - 2 * n;
				vstack.length = vstack.length - n;
				lstack.length = lstack.length - n;
			}
			_token_stack:
				function lex() {
					var token;
					token = lexer.lex() || EOF;
					if (typeof token !== 'number') {
						token = self.symbols_[token] || token;
					}
					return token;
				}
			var symbol, preErrorSymbol, state, action, a, r, yyval = {}, p, len, newState, expected;
			while (true) {
				state = stack[stack.length - 1];
				if (this.defaultActions[state]) {
					action = this.defaultActions[state];
				} else {
					if (symbol === null || typeof symbol == 'undefined') {
						symbol = lex();
					}
					action = table[state] && table[state][symbol];
				}
							if (typeof action === 'undefined' || !action.length || !action[0]) {
						var errStr = '';
						expected = [];
						for (p in table[state]) {
							if (this.terminals_[p] && p > TERROR) {
								expected.push('\'' + this.terminals_[p] + '\'');
							}
						}
						if (lexer.showPosition) {
							errStr = 'Parse error on line ' + (yylineno + 1) + ':\n' + lexer.showPosition() + '\nExpecting ' + expected.join(', ') + ', got \'' + (this.terminals_[symbol] || symbol) + '\'';
						} else {
							errStr = 'Parse error on line ' + (yylineno + 1) + ': Unexpected ' + (symbol == EOF ? 'end of input' : '\'' + (this.terminals_[symbol] || symbol) + '\'');
						}
						this.parseError(errStr, {
							text: lexer.match,
							token: this.terminals_[symbol] || symbol,
							line: lexer.yylineno,
							loc: yyloc,
							expected: expected
						});
					}
				if (action[0] instanceof Array && action.length > 1) {
					throw new Error('Parse Error: multiple actions possible at state: ' + state + ', token: ' + symbol);
				}
				switch (action[0]) {
				case 1:
					stack.push(symbol);
					vstack.push(lexer.yytext);
					lstack.push(lexer.yylloc);
					stack.push(action[1]);
					symbol = null;
					if (!preErrorSymbol) {
						yyleng = lexer.yyleng;
						yytext = lexer.yytext;
						yylineno = lexer.yylineno;
						yyloc = lexer.yylloc;
						if (recovering > 0) {
							recovering--;
						}
					} else {
						symbol = preErrorSymbol;
						preErrorSymbol = null;
					}
					break;
				case 2:
					len = this.productions_[action[1]][1];
					yyval.$ = vstack[vstack.length - len];
					yyval._$ = {
						first_line: lstack[lstack.length - (len || 1)].first_line,
						last_line: lstack[lstack.length - 1].last_line,
						first_column: lstack[lstack.length - (len || 1)].first_column,
						last_column: lstack[lstack.length - 1].last_column
					};
					if (ranges) {
						yyval._$.range = [
							lstack[lstack.length - (len || 1)].range[0],
							lstack[lstack.length - 1].range[1]
						];
					}
					r = this.performAction.apply(yyval, [
						yytext,
						yyleng,
						yylineno,
						sharedState.yy,
						action[1],
						vstack,
						lstack
					].concat(args));
					if (typeof r !== 'undefined') {
						return r;
					}
					if (len) {
						stack = stack.slice(0, -1 * len * 2);
						vstack = vstack.slice(0, -1 * len);
						lstack = lstack.slice(0, -1 * len);
					}
					stack.push(this.productions_[action[1]][0]);
					vstack.push(yyval.$);
					lstack.push(yyval._$);
					newState = table[stack[stack.length - 2]][stack[stack.length - 1]];
					stack.push(newState);
					break;
				case 3:
					return true;
				}
			}
			return true;
		}};

		function Parser () {
		  this.yy = {};
		}
		Parser.prototype = parser;parser.Parser = Parser;
		return new Parser;
		})();


//		if (typeof require !== 'undefined' && typeof exports !== 'undefined') {
		exports.parser = parser;
		exports.Parser = parser.Parser;
		exports.parse = function () { return parser.parse.apply(parser, arguments); };
//		exports.main = function commonjsMain(args) {
//			if (!args[1]) {
//				console.log('Usage: '+args[0]+' FILE');
//				process.exit(1);
//			}
//			var source = require('fs').readFileSync(require('path').normalize(args[1]), "utf8");
//			return exports.parser.parse(source);
//		};
//		if (typeof module !== 'undefined' && require.main === module) {
//		  exports.main(process.argv.slice(1));
//		}
//		}
		
		return exports;
	};
	//#endregion

	//#region URL: /scope
	modules['/scope'] = function() {
	  var exports = {};
	  var Scope,
		indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

	  exports.Scope = Scope = (function() {
		function Scope(parent, expressions, method, referencedVars) {
		  var ref, ref1;
		  this.parent = parent;
		  this.expressions = expressions;
		  this.method = method;
		  this.referencedVars = referencedVars;
		  this.variables = [
			{
			  name: 'arguments',
			  type: 'arguments'
			}
		  ];
		  this.positions = {};
		  if (!this.parent) {
			this.utilities = {};
		  }
		  this.root = (ref = (ref1 = this.parent) != null ? ref1.root : void 0) != null ? ref : this;
		}

		Scope.prototype.add = function(name, type, immediate) {
		  if (this.shared && !immediate) {
			return this.parent.add(name, type, immediate);
		  }
		  if (Object.prototype.hasOwnProperty.call(this.positions, name)) {
			return this.variables[this.positions[name]].type = type;
		  } else {
			return this.positions[name] = this.variables.push({
			  name: name,
			  type: type
			}) - 1;
		  }
		};

		Scope.prototype.namedMethod = function() {
		  var ref;
		  if (((ref = this.method) != null ? ref.name : void 0) || !this.parent) {
			return this.method;
		  }
		  return this.parent.namedMethod();
		};

		Scope.prototype.find = function(name) {
		  if (this.check(name)) {
			return true;
		  }
		  this.add(name, 'var');
		  return false;
		};

		Scope.prototype.parameter = function(name) {
		  if (this.shared && this.parent.check(name, true)) {
			return;
		  }
		  return this.add(name, 'param');
		};

		Scope.prototype.check = function(name) {
		  var ref;
		  return !!(this.type(name) || ((ref = this.parent) != null ? ref.check(name) : void 0));
		};

		Scope.prototype.temporary = function(name, index, single) {
		  if (single == null) {
			single = false;
		  }
		  if (single) {
			return (index + parseInt(name, 36)).toString(36).replace(/\d/g, 'a');
		  } else {
			return name + (index || '');
		  }
		};

		Scope.prototype.type = function(name) {
		  var i, len, ref, v;
		  ref = this.variables;
		  for (i = 0, len = ref.length; i < len; i++) {
			v = ref[i];
			if (v.name === name) {
			  return v.type;
			}
		  }
		  return null;
		};

		Scope.prototype.freeVariable = function(name, options) {
		  var index, ref, temp;
		  if (options == null) {
			options = {};
		  }
		  index = 0;
		  while (true) {
			temp = this.temporary(name, index, options.single);
			if (!(this.check(temp) || indexOf.call(this.root.referencedVars, temp) >= 0)) {
			  break;
			}
			index++;
		  }
		  if ((ref = options.reserve) != null ? ref : true) {
			this.add(temp, 'var', true);
		  }
		  return temp;
		};

		Scope.prototype.assign = function(name, value) {
		  this.add(name, {
			value: value,
			assigned: true
		  }, true);
		  return this.hasAssignments = true;
		};

		Scope.prototype.hasDeclarations = function() {
		  return !!this.declaredVariables().length;
		};

		Scope.prototype.declaredVariables = function() {
		  var v;
		  return ((function() {
			var i, len, ref, results;
			ref = this.variables;
			results = [];
			for (i = 0, len = ref.length; i < len; i++) {
			  v = ref[i];
			  if (v.type === 'var') {
				results.push(v.name);
			  }
			}
			return results;
		  }).call(this)).sort();
		};

		Scope.prototype.assignedVariables = function() {
		  var i, len, ref, results, v;
		  ref = this.variables;
		  results = [];
		  for (i = 0, len = ref.length; i < len; i++) {
			v = ref[i];
			if (v.type.assigned) {
			  results.push(v.name + " = " + v.type.value);
			}
		  }
		  return results;
		};

		return Scope;

	  })();
  
	  return exports;
	};
	//#endregion

	//#region URL: /nodes
	modules['/nodes'] = function() {
	  var exports = {};
	  var Access, Arr, Assign, Base, Block, Call, Class, Code, CodeFragment, Comment, Existence, Expansion, Extends, For, HEXNUM, IDENTIFIER, IS_REGEX, IS_STRING, If, In, Index, LEVEL_ACCESS, LEVEL_COND, LEVEL_LIST, LEVEL_OP, LEVEL_PAREN, LEVEL_TOP, Literal, NEGATE, NO, NUMBER, Obj, Op, Param, Parens, RESERVED, Range, Return, SIMPLENUM, STRICT_PROSCRIBED, Scope, Slice, Splat, Switch, TAB, THIS, Throw, Try, UTILITIES, Value, While, YES, addLocationDataFn, compact, del, ends, extend, flatten, fragmentsToText, isComplexOrAssignable, isLiteralArguments, isLiteralThis, locationDataToString, merge, multident, parseNum, ref1, ref2, some, starts, throwSyntaxError, unfoldSoak, utility,
		extend1 = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
		hasProp = {}.hasOwnProperty,
		indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; },
		slice = [].slice;

	  Error.stackTraceLimit = Infinity;

	  Scope = require('/scope').Scope;

	  ref1 = require('/lexer'), RESERVED = ref1.RESERVED, STRICT_PROSCRIBED = ref1.STRICT_PROSCRIBED;

	  ref2 = require('/helpers'), compact = ref2.compact, flatten = ref2.flatten, extend = ref2.extend, merge = ref2.merge, del = ref2.del, starts = ref2.starts, ends = ref2.ends, some = ref2.some, addLocationDataFn = ref2.addLocationDataFn, locationDataToString = ref2.locationDataToString, throwSyntaxError = ref2.throwSyntaxError;

	  exports.extend = extend;

	  exports.addLocationDataFn = addLocationDataFn;

	  YES = function() {
		return true;
	  };

	  NO = function() {
		return false;
	  };

	  THIS = function() {
		return this;
	  };

	  NEGATE = function() {
		this.negated = !this.negated;
		return this;
	  };

	  exports.CodeFragment = CodeFragment = (function() {
		function CodeFragment(parent, code) {
		  var ref3;
		  this.code = "" + code;
		  this.locationData = parent != null ? parent.locationData : void 0;
		  this.type = (parent != null ? (ref3 = parent.constructor) != null ? ref3.name : void 0 : void 0) || 'unknown';
		}

		CodeFragment.prototype.toString = function() {
		  return "" + this.code + (this.locationData ? ": " + locationDataToString(this.locationData) : '');
		};

		return CodeFragment;

	  })();

	  fragmentsToText = function(fragments) {
		var fragment;
		return ((function() {
		  var j, len1, results;
		  results = [];
		  for (j = 0, len1 = fragments.length; j < len1; j++) {
			fragment = fragments[j];
			results.push(fragment.code);
		  }
		  return results;
		})()).join('');
	  };

	  exports.Base = Base = (function() {
		function Base() {}

		Base.prototype.compile = function(o, lvl) {
		  return fragmentsToText(this.compileToFragments(o, lvl));
		};

		Base.prototype.compileToFragments = function(o, lvl) {
		  var node;
		  o = extend({}, o);
		  if (lvl) {
			o.level = lvl;
		  }
		  node = this.unfoldSoak(o) || this;
		  node.tab = o.indent;
		  if (o.level === LEVEL_TOP || !node.isStatement(o)) {
			return node.compileNode(o);
		  } else {
			return node.compileClosure(o);
		  }
		};

		Base.prototype.compileClosure = function(o) {
		  var args, argumentsNode, func, jumpNode, meth, parts, ref3;
		  if (jumpNode = this.jumps()) {
			jumpNode.error('cannot use a pure statement in an expression');
		  }
		  o.sharedScope = true;
		  func = new Code([], Block.wrap([this]));
		  args = [];
		  if ((argumentsNode = this.contains(isLiteralArguments)) || this.contains(isLiteralThis)) {
			args = [new Literal('this')];
			if (argumentsNode) {
			  meth = 'apply';
			  args.push(new Literal('arguments'));
			} else {
			  meth = 'call';
			}
			func = new Value(func, [new Access(new Literal(meth))]);
		  }
		  parts = (new Call(func, args)).compileNode(o);
		  if (func.isGenerator || ((ref3 = func.base) != null ? ref3.isGenerator : void 0)) {
			parts.unshift(this.makeCode("(yield* "));
			parts.push(this.makeCode(")"));
		  }
		  return parts;
		};

		Base.prototype.cache = function(o, level, isComplex) {
		  var complex, ref, sub;
		  complex = isComplex != null ? isComplex(this) : this.isComplex();
		  if (complex) {
			ref = new Literal(o.scope.freeVariable('ref'));
			sub = new Assign(ref, this);
			if (level) {
			  return [sub.compileToFragments(o, level), [this.makeCode(ref.value)]];
			} else {
			  return [sub, ref];
			}
		  } else {
			ref = level ? this.compileToFragments(o, level) : this;
			return [ref, ref];
		  }
		};

		Base.prototype.cacheToCodeFragments = function(cacheValues) {
		  return [fragmentsToText(cacheValues[0]), fragmentsToText(cacheValues[1])];
		};

		Base.prototype.makeReturn = function(res) {
		  var me;
		  me = this.unwrapAll();
		  if (res) {
			return new Call(new Literal(res + ".push"), [me]);
		  } else {
			return new Return(me);
		  }
		};

		Base.prototype.contains = function(pred) {
		  var node;
		  node = void 0;
		  this.traverseChildren(false, function(n) {
			if (pred(n)) {
			  node = n;
			  return false;
			}
		  });
		  return node;
		};

		Base.prototype.lastNonComment = function(list) {
		  var i;
		  i = list.length;
		  while (i--) {
			if (!(list[i] instanceof Comment)) {
			  return list[i];
			}
		  }
		  return null;
		};

		Base.prototype.toString = function(idt, name) {
		  var tree;
		  if (idt == null) {
			idt = '';
		  }
		  if (name == null) {
			name = this.constructor.name;
		  }
		  tree = '\n' + idt + name;
		  if (this.soak) {
			tree += '?';
		  }
		  this.eachChild(function(node) {
			return tree += node.toString(idt + TAB);
		  });
		  return tree;
		};

		Base.prototype.eachChild = function(func) {
		  var attr, child, j, k, len1, len2, ref3, ref4;
		  if (!this.children) {
			return this;
		  }
		  ref3 = this.children;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			attr = ref3[j];
			if (this[attr]) {
			  ref4 = flatten([this[attr]]);
			  for (k = 0, len2 = ref4.length; k < len2; k++) {
				child = ref4[k];
				if (func(child) === false) {
				  return this;
				}
			  }
			}
		  }
		  return this;
		};

		Base.prototype.traverseChildren = function(crossScope, func) {
		  return this.eachChild(function(child) {
			var recur;
			recur = func(child);
			if (recur !== false) {
			  return child.traverseChildren(crossScope, func);
			}
		  });
		};

		Base.prototype.invert = function() {
		  return new Op('!', this);
		};

		Base.prototype.unwrapAll = function() {
		  var node;
		  node = this;
		  while (node !== (node = node.unwrap())) {
			continue;
		  }
		  return node;
		};

		Base.prototype.children = [];

		Base.prototype.isStatement = NO;

		Base.prototype.jumps = NO;

		Base.prototype.isComplex = YES;

		Base.prototype.isChainable = NO;

		Base.prototype.isAssignable = NO;

		Base.prototype.unwrap = THIS;

		Base.prototype.unfoldSoak = NO;

		Base.prototype.assigns = NO;

		Base.prototype.updateLocationDataIfMissing = function(locationData) {
		  if (this.locationData) {
			return this;
		  }
		  this.locationData = locationData;
		  return this.eachChild(function(child) {
			return child.updateLocationDataIfMissing(locationData);
		  });
		};

		Base.prototype.error = function(message) {
		  return throwSyntaxError(message, this.locationData);
		};

		Base.prototype.makeCode = function(code) {
		  return new CodeFragment(this, code);
		};

		Base.prototype.wrapInBraces = function(fragments) {
		  return [].concat(this.makeCode('('), fragments, this.makeCode(')'));
		};

		Base.prototype.joinFragmentArrays = function(fragmentsList, joinStr) {
		  var answer, fragments, i, j, len1;
		  answer = [];
		  for (i = j = 0, len1 = fragmentsList.length; j < len1; i = ++j) {
			fragments = fragmentsList[i];
			if (i) {
			  answer.push(this.makeCode(joinStr));
			}
			answer = answer.concat(fragments);
		  }
		  return answer;
		};

		return Base;

	  })();

	  exports.Block = Block = (function(superClass1) {
		extend1(Block, superClass1);

		function Block(nodes) {
		  this.expressions = compact(flatten(nodes || []));
		}

		Block.prototype.children = ['expressions'];

		Block.prototype.push = function(node) {
		  this.expressions.push(node);
		  return this;
		};

		Block.prototype.pop = function() {
		  return this.expressions.pop();
		};

		Block.prototype.unshift = function(node) {
		  this.expressions.unshift(node);
		  return this;
		};

		Block.prototype.unwrap = function() {
		  if (this.expressions.length === 1) {
			return this.expressions[0];
		  } else {
			return this;
		  }
		};

		Block.prototype.isEmpty = function() {
		  return !this.expressions.length;
		};

		Block.prototype.isStatement = function(o) {
		  var exp, j, len1, ref3;
		  ref3 = this.expressions;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			exp = ref3[j];
			if (exp.isStatement(o)) {
			  return true;
			}
		  }
		  return false;
		};

		Block.prototype.jumps = function(o) {
		  var exp, j, jumpNode, len1, ref3;
		  ref3 = this.expressions;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			exp = ref3[j];
			if (jumpNode = exp.jumps(o)) {
			  return jumpNode;
			}
		  }
		};

		Block.prototype.makeReturn = function(res) {
		  var expr, len;
		  len = this.expressions.length;
		  while (len--) {
			expr = this.expressions[len];
			if (!(expr instanceof Comment)) {
			  this.expressions[len] = expr.makeReturn(res);
			  if (expr instanceof Return && !expr.expression) {
				this.expressions.splice(len, 1);
			  }
			  break;
			}
		  }
		  return this;
		};

		Block.prototype.compileToFragments = function(o, level) {
		  if (o == null) {
			o = {};
		  }
		  if (o.scope) {
			return Block.__super__.compileToFragments.call(this, o, level);
		  } else {
			return this.compileRoot(o);
		  }
		};

		Block.prototype.compileNode = function(o) {
		  var answer, compiledNodes, fragments, index, j, len1, node, ref3, top;
		  this.tab = o.indent;
		  top = o.level === LEVEL_TOP;
		  compiledNodes = [];
		  ref3 = this.expressions;
		  for (index = j = 0, len1 = ref3.length; j < len1; index = ++j) {
			node = ref3[index];
			node = node.unwrapAll();
			node = node.unfoldSoak(o) || node;
			if (node instanceof Block) {
			  compiledNodes.push(node.compileNode(o));
			} else if (top) {
			  node.front = true;
			  fragments = node.compileToFragments(o);
			  if (!node.isStatement(o)) {
				fragments.unshift(this.makeCode("" + this.tab));
				fragments.push(this.makeCode(";"));
			  }
			  compiledNodes.push(fragments);
			} else {
			  compiledNodes.push(node.compileToFragments(o, LEVEL_LIST));
			}
		  }
		  if (top) {
			if (this.spaced) {
			  return [].concat(this.joinFragmentArrays(compiledNodes, '\n\n'), this.makeCode("\n"));
			} else {
			  return this.joinFragmentArrays(compiledNodes, '\n');
			}
		  }
		  if (compiledNodes.length) {
			answer = this.joinFragmentArrays(compiledNodes, ', ');
		  } else {
			answer = [this.makeCode("void 0")];
		  }
		  if (compiledNodes.length > 1 && o.level >= LEVEL_LIST) {
			return this.wrapInBraces(answer);
		  } else {
			return answer;
		  }
		};

		Block.prototype.compileRoot = function(o) {
		  var exp, fragments, i, j, len1, name, prelude, preludeExps, ref3, ref4, rest;
		  o.indent = o.bare ? '' : TAB;
		  o.level = LEVEL_TOP;
		  this.spaced = true;
		  o.scope = new Scope(null, this, null, (ref3 = o.referencedVars) != null ? ref3 : []);
		  ref4 = o.locals || [];
		  for (j = 0, len1 = ref4.length; j < len1; j++) {
			name = ref4[j];
			o.scope.parameter(name);
		  }
		  prelude = [];
		  if (!o.bare) {
			preludeExps = (function() {
			  var k, len2, ref5, results;
			  ref5 = this.expressions;
			  results = [];
			  for (i = k = 0, len2 = ref5.length; k < len2; i = ++k) {
				exp = ref5[i];
				if (!(exp.unwrap() instanceof Comment)) {
				  break;
				}
				results.push(exp);
			  }
			  return results;
			}).call(this);
			rest = this.expressions.slice(preludeExps.length);
			this.expressions = preludeExps;
			if (preludeExps.length) {
			  prelude = this.compileNode(merge(o, {
				indent: ''
			  }));
			  prelude.push(this.makeCode("\n"));
			}
			this.expressions = rest;
		  }
		  fragments = this.compileWithDeclarations(o);
		  if (o.bare) {
			return fragments;
		  }
		  return [].concat(prelude, this.makeCode("(function() {\n"), fragments, this.makeCode("\n}).call(this);\n"));
		};

		Block.prototype.compileWithDeclarations = function(o) {
		  var assigns, declars, exp, fragments, i, j, len1, post, ref3, ref4, ref5, rest, scope, spaced;
		  fragments = [];
		  post = [];
		  ref3 = this.expressions;
		  for (i = j = 0, len1 = ref3.length; j < len1; i = ++j) {
			exp = ref3[i];
			exp = exp.unwrap();
			if (!(exp instanceof Comment || exp instanceof Literal)) {
			  break;
			}
		  }
		  o = merge(o, {
			level: LEVEL_TOP
		  });
		  if (i) {
			rest = this.expressions.splice(i, 9e9);
			ref4 = [this.spaced, false], spaced = ref4[0], this.spaced = ref4[1];
			ref5 = [this.compileNode(o), spaced], fragments = ref5[0], this.spaced = ref5[1];
			this.expressions = rest;
		  }
		  post = this.compileNode(o);
		  scope = o.scope;
		  if (scope.expressions === this) {
			declars = o.scope.hasDeclarations();
			assigns = scope.hasAssignments;
			if (declars || assigns) {
			  if (i) {
				fragments.push(this.makeCode('\n'));
			  }
			  fragments.push(this.makeCode(this.tab + "var "));
			  if (declars) {
				fragments.push(this.makeCode(scope.declaredVariables().join(', ')));
			  }
			  if (assigns) {
				if (declars) {
				  fragments.push(this.makeCode(",\n" + (this.tab + TAB)));
				}
				fragments.push(this.makeCode(scope.assignedVariables().join(",\n" + (this.tab + TAB))));
			  }
			  fragments.push(this.makeCode(";\n" + (this.spaced ? '\n' : '')));
			} else if (fragments.length && post.length) {
			  fragments.push(this.makeCode("\n"));
			}
		  }
		  return fragments.concat(post);
		};

		Block.wrap = function(nodes) {
		  if (nodes.length === 1 && nodes[0] instanceof Block) {
			return nodes[0];
		  }
		  return new Block(nodes);
		};

		return Block;

	  })(Base);

	  exports.Literal = Literal = (function(superClass1) {
		extend1(Literal, superClass1);

		function Literal(value1) {
		  this.value = value1;
		}

		Literal.prototype.makeReturn = function() {
		  if (this.isStatement()) {
			return this;
		  } else {
			return Literal.__super__.makeReturn.apply(this, arguments);
		  }
		};

		Literal.prototype.isAssignable = function() {
		  return IDENTIFIER.test(this.value);
		};

		Literal.prototype.isStatement = function() {
		  var ref3;
		  return (ref3 = this.value) === 'break' || ref3 === 'continue' || ref3 === 'debugger';
		};

		Literal.prototype.isComplex = NO;

		Literal.prototype.assigns = function(name) {
		  return name === this.value;
		};

		Literal.prototype.jumps = function(o) {
		  if (this.value === 'break' && !((o != null ? o.loop : void 0) || (o != null ? o.block : void 0))) {
			return this;
		  }
		  if (this.value === 'continue' && !(o != null ? o.loop : void 0)) {
			return this;
		  }
		};

		Literal.prototype.compileNode = function(o) {
		  var answer, code, ref3;
		  code = this.value === 'this' ? ((ref3 = o.scope.method) != null ? ref3.bound : void 0) ? o.scope.method.context : this.value : this.value.reserved ? "\"" + this.value + "\"" : this.value;
		  answer = this.isStatement() ? "" + this.tab + code + ";" : code;
		  return [this.makeCode(answer)];
		};

		Literal.prototype.toString = function() {
		  return ' "' + this.value + '"';
		};

		return Literal;

	  })(Base);

	  exports.Undefined = (function(superClass1) {
		extend1(Undefined, superClass1);

		function Undefined() {
		  return Undefined.__super__.constructor.apply(this, arguments);
		}

		Undefined.prototype.isAssignable = NO;

		Undefined.prototype.isComplex = NO;

		Undefined.prototype.compileNode = function(o) {
		  return [this.makeCode(o.level >= LEVEL_ACCESS ? '(void 0)' : 'void 0')];
		};

		return Undefined;

	  })(Base);

	  exports.Null = (function(superClass1) {
		extend1(Null, superClass1);

		function Null() {
		  return Null.__super__.constructor.apply(this, arguments);
		}

		Null.prototype.isAssignable = NO;

		Null.prototype.isComplex = NO;

		Null.prototype.compileNode = function() {
		  return [this.makeCode("null")];
		};

		return Null;

	  })(Base);

	  exports.Bool = (function(superClass1) {
		extend1(Bool, superClass1);

		Bool.prototype.isAssignable = NO;

		Bool.prototype.isComplex = NO;

		Bool.prototype.compileNode = function() {
		  return [this.makeCode(this.val)];
		};

		function Bool(val1) {
		  this.val = val1;
		}

		return Bool;

	  })(Base);

	  exports.Return = Return = (function(superClass1) {
		extend1(Return, superClass1);

		function Return(expression) {
		  this.expression = expression;
		}

		Return.prototype.children = ['expression'];

		Return.prototype.isStatement = YES;

		Return.prototype.makeReturn = THIS;

		Return.prototype.jumps = THIS;

		Return.prototype.compileToFragments = function(o, level) {
		  var expr, ref3;
		  expr = (ref3 = this.expression) != null ? ref3.makeReturn() : void 0;
		  if (expr && !(expr instanceof Return)) {
			return expr.compileToFragments(o, level);
		  } else {
			return Return.__super__.compileToFragments.call(this, o, level);
		  }
		};

		Return.prototype.compileNode = function(o) {
		  var answer, exprIsYieldReturn, ref3;
		  answer = [];
		  exprIsYieldReturn = (ref3 = this.expression) != null ? typeof ref3.isYieldReturn === "function" ? ref3.isYieldReturn() : void 0 : void 0;
		  if (!exprIsYieldReturn) {
			answer.push(this.makeCode(this.tab + ("return" + (this.expression ? " " : ""))));
		  }
		  if (this.expression) {
			answer = answer.concat(this.expression.compileToFragments(o, LEVEL_PAREN));
		  }
		  if (!exprIsYieldReturn) {
			answer.push(this.makeCode(";"));
		  }
		  return answer;
		};

		return Return;

	  })(Base);

	  exports.Value = Value = (function(superClass1) {
		extend1(Value, superClass1);

		function Value(base, props, tag) {
		  if (!props && base instanceof Value) {
			return base;
		  }
		  this.base = base;
		  this.properties = props || [];
		  if (tag) {
			this[tag] = true;
		  }
		  return this;
		}

		Value.prototype.children = ['base', 'properties'];

		Value.prototype.add = function(props) {
		  this.properties = this.properties.concat(props);
		  return this;
		};

		Value.prototype.hasProperties = function() {
		  return !!this.properties.length;
		};

		Value.prototype.bareLiteral = function(type) {
		  return !this.properties.length && this.base instanceof type;
		};

		Value.prototype.isArray = function() {
		  return this.bareLiteral(Arr);
		};

		Value.prototype.isRange = function() {
		  return this.bareLiteral(Range);
		};

		Value.prototype.isComplex = function() {
		  return this.hasProperties() || this.base.isComplex();
		};

		Value.prototype.isAssignable = function() {
		  return this.hasProperties() || this.base.isAssignable();
		};

		Value.prototype.isSimpleNumber = function() {
		  return this.bareLiteral(Literal) && SIMPLENUM.test(this.base.value);
		};

		Value.prototype.isString = function() {
		  return this.bareLiteral(Literal) && IS_STRING.test(this.base.value);
		};

		Value.prototype.isRegex = function() {
		  return this.bareLiteral(Literal) && IS_REGEX.test(this.base.value);
		};

		Value.prototype.isAtomic = function() {
		  var j, len1, node, ref3;
		  ref3 = this.properties.concat(this.base);
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			node = ref3[j];
			if (node.soak || node instanceof Call) {
			  return false;
			}
		  }
		  return true;
		};

		Value.prototype.isNotCallable = function() {
		  return this.isSimpleNumber() || this.isString() || this.isRegex() || this.isArray() || this.isRange() || this.isSplice() || this.isObject();
		};

		Value.prototype.isStatement = function(o) {
		  return !this.properties.length && this.base.isStatement(o);
		};

		Value.prototype.assigns = function(name) {
		  return !this.properties.length && this.base.assigns(name);
		};

		Value.prototype.jumps = function(o) {
		  return !this.properties.length && this.base.jumps(o);
		};

		Value.prototype.isObject = function(onlyGenerated) {
		  if (this.properties.length) {
			return false;
		  }
		  return (this.base instanceof Obj) && (!onlyGenerated || this.base.generated);
		};

		Value.prototype.isSplice = function() {
		  var lastProp, ref3;
		  ref3 = this.properties, lastProp = ref3[ref3.length - 1];
		  return lastProp instanceof Slice;
		};

		Value.prototype.looksStatic = function(className) {
		  var ref3;
		  return this.base.value === className && this.properties.length === 1 && ((ref3 = this.properties[0].name) != null ? ref3.value : void 0) !== 'prototype';
		};

		Value.prototype.unwrap = function() {
		  if (this.properties.length) {
			return this;
		  } else {
			return this.base;
		  }
		};

		Value.prototype.cacheReference = function(o) {
		  var base, bref, name, nref, ref3;
		  ref3 = this.properties, name = ref3[ref3.length - 1];
		  if (this.properties.length < 2 && !this.base.isComplex() && !(name != null ? name.isComplex() : void 0)) {
			return [this, this];
		  }
		  base = new Value(this.base, this.properties.slice(0, -1));
		  if (base.isComplex()) {
			bref = new Literal(o.scope.freeVariable('base'));
			base = new Value(new Parens(new Assign(bref, base)));
		  }
		  if (!name) {
			return [base, bref];
		  }
		  if (name.isComplex()) {
			nref = new Literal(o.scope.freeVariable('name'));
			name = new Index(new Assign(nref, name.index));
			nref = new Index(nref);
		  }
		  return [base.add(name), new Value(bref || base.base, [nref || name])];
		};

		Value.prototype.compileNode = function(o) {
		  var fragments, j, len1, prop, props;
		  this.base.front = this.front;
		  props = this.properties;
		  fragments = this.base.compileToFragments(o, (props.length ? LEVEL_ACCESS : null));
		  if ((this.base instanceof Parens || props.length) && SIMPLENUM.test(fragmentsToText(fragments))) {
			fragments.push(this.makeCode('.'));
		  }
		  for (j = 0, len1 = props.length; j < len1; j++) {
			prop = props[j];
			fragments.push.apply(fragments, prop.compileToFragments(o));
		  }
		  return fragments;
		};

		Value.prototype.unfoldSoak = function(o) {
		  return this.unfoldedSoak != null ? this.unfoldedSoak : this.unfoldedSoak = (function(_this) {
			return function() {
			  var fst, i, ifn, j, len1, prop, ref, ref3, ref4, snd;
			  if (ifn = _this.base.unfoldSoak(o)) {
				(ref3 = ifn.body.properties).push.apply(ref3, _this.properties);
				return ifn;
			  }
			  ref4 = _this.properties;
			  for (i = j = 0, len1 = ref4.length; j < len1; i = ++j) {
				prop = ref4[i];
				if (!prop.soak) {
				  continue;
				}
				prop.soak = false;
				fst = new Value(_this.base, _this.properties.slice(0, i));
				snd = new Value(_this.base, _this.properties.slice(i));
				if (fst.isComplex()) {
				  ref = new Literal(o.scope.freeVariable('ref'));
				  fst = new Parens(new Assign(ref, fst));
				  snd.base = ref;
				}
				return new If(new Existence(fst), snd, {
				  soak: true
				});
			  }
			  return false;
			};
		  })(this)();
		};

		return Value;

	  })(Base);

	  exports.Comment = Comment = (function(superClass1) {
		extend1(Comment, superClass1);

		function Comment(comment1) {
		  this.comment = comment1;
		}

		Comment.prototype.isStatement = YES;

		Comment.prototype.makeReturn = THIS;

		Comment.prototype.compileNode = function(o, level) {
		  var code, comment;
		  comment = this.comment.replace(/^(\s*)# /gm, "$1 * ");
		  code = "/*" + (multident(comment, this.tab)) + (indexOf.call(comment, '\n') >= 0 ? "\n" + this.tab : '') + " */";
		  if ((level || o.level) === LEVEL_TOP) {
			code = o.indent + code;
		  }
		  return [this.makeCode("\n"), this.makeCode(code)];
		};

		return Comment;

	  })(Base);

	  exports.Call = Call = (function(superClass1) {
		extend1(Call, superClass1);

		function Call(variable, args1, soak) {
		  this.args = args1 != null ? args1 : [];
		  this.soak = soak;
		  this.isNew = false;
		  this.isSuper = variable === 'super';
		  this.variable = this.isSuper ? null : variable;
		  if (variable instanceof Value && variable.isNotCallable()) {
			variable.error("literal is not a function");
		  }
		}

		Call.prototype.children = ['variable', 'args'];

		Call.prototype.newInstance = function() {
		  var base, ref3;
		  base = ((ref3 = this.variable) != null ? ref3.base : void 0) || this.variable;
		  if (base instanceof Call && !base.isNew) {
			base.newInstance();
		  } else {
			this.isNew = true;
		  }
		  return this;
		};

		Call.prototype.superReference = function(o) {
		  var accesses, base, bref, klass, method, name, nref, variable;
		  method = o.scope.namedMethod();
		  if (method != null ? method.klass : void 0) {
			klass = method.klass, name = method.name, variable = method.variable;
			if (klass.isComplex()) {
			  bref = new Literal(o.scope.parent.freeVariable('base'));
			  base = new Value(new Parens(new Assign(bref, klass)));
			  variable.base = base;
			  variable.properties.splice(0, klass.properties.length);
			}
			if (name.isComplex() || (name instanceof Index && name.index.isAssignable())) {
			  nref = new Literal(o.scope.parent.freeVariable('name'));
			  name = new Index(new Assign(nref, name.index));
			  variable.properties.pop();
			  variable.properties.push(name);
			}
			accesses = [new Access(new Literal('__super__'))];
			if (method["static"]) {
			  accesses.push(new Access(new Literal('constructor')));
			}
			accesses.push(nref != null ? new Index(nref) : name);
			return (new Value(bref != null ? bref : klass, accesses)).compile(o);
		  } else if (method != null ? method.ctor : void 0) {
			return method.name + ".__super__.constructor";
		  } else {
			return this.error('cannot call super outside of an instance method.');
		  }
		};

		Call.prototype.superThis = function(o) {
		  var method;
		  method = o.scope.method;
		  return (method && !method.klass && method.context) || "this";
		};

		Call.prototype.unfoldSoak = function(o) {
		  var call, ifn, j, left, len1, list, ref3, ref4, rite;
		  if (this.soak) {
			if (this.variable) {
			  if (ifn = unfoldSoak(o, this, 'variable')) {
				return ifn;
			  }
			  ref3 = new Value(this.variable).cacheReference(o), left = ref3[0], rite = ref3[1];
			} else {
			  left = new Literal(this.superReference(o));
			  rite = new Value(left);
			}
			rite = new Call(rite, this.args);
			rite.isNew = this.isNew;
			left = new Literal("typeof " + (left.compile(o)) + " === \"function\"");
			return new If(left, new Value(rite), {
			  soak: true
			});
		  }
		  call = this;
		  list = [];
		  while (true) {
			if (call.variable instanceof Call) {
			  list.push(call);
			  call = call.variable;
			  continue;
			}
			if (!(call.variable instanceof Value)) {
			  break;
			}
			list.push(call);
			if (!((call = call.variable.base) instanceof Call)) {
			  break;
			}
		  }
		  ref4 = list.reverse();
		  for (j = 0, len1 = ref4.length; j < len1; j++) {
			call = ref4[j];
			if (ifn) {
			  if (call.variable instanceof Call) {
				call.variable = ifn;
			  } else {
				call.variable.base = ifn;
			  }
			}
			ifn = unfoldSoak(o, call, 'variable');
		  }
		  return ifn;
		};

		Call.prototype.compileNode = function(o) {
		  var arg, argIndex, compiledArgs, compiledArray, fragments, j, len1, preface, ref3, ref4;
		  if ((ref3 = this.variable) != null) {
			ref3.front = this.front;
		  }
		  compiledArray = Splat.compileSplattedArray(o, this.args, true);
		  if (compiledArray.length) {
			return this.compileSplat(o, compiledArray);
		  }
		  compiledArgs = [];
		  ref4 = this.args;
		  for (argIndex = j = 0, len1 = ref4.length; j < len1; argIndex = ++j) {
			arg = ref4[argIndex];
			if (argIndex) {
			  compiledArgs.push(this.makeCode(", "));
			}
			compiledArgs.push.apply(compiledArgs, arg.compileToFragments(o, LEVEL_LIST));
		  }
		  fragments = [];
		  if (this.isSuper) {
			preface = this.superReference(o) + (".call(" + (this.superThis(o)));
			if (compiledArgs.length) {
			  preface += ", ";
			}
			fragments.push(this.makeCode(preface));
		  } else {
			if (this.isNew) {
			  fragments.push(this.makeCode('new '));
			}
			fragments.push.apply(fragments, this.variable.compileToFragments(o, LEVEL_ACCESS));
			fragments.push(this.makeCode("("));
		  }
		  fragments.push.apply(fragments, compiledArgs);
		  fragments.push(this.makeCode(")"));
		  return fragments;
		};

		Call.prototype.compileSplat = function(o, splatArgs) {
		  var answer, base, fun, idt, name, ref;
		  if (this.isSuper) {
			return [].concat(this.makeCode((this.superReference(o)) + ".apply(" + (this.superThis(o)) + ", "), splatArgs, this.makeCode(")"));
		  }
		  if (this.isNew) {
			idt = this.tab + TAB;
			return [].concat(this.makeCode("(function(func, args, ctor) {\n" + idt + "ctor.prototype = func.prototype;\n" + idt + "var child = new ctor, result = func.apply(child, args);\n" + idt + "return Object(result) === result ? result : child;\n" + this.tab + "})("), this.variable.compileToFragments(o, LEVEL_LIST), this.makeCode(", "), splatArgs, this.makeCode(", function(){})"));
		  }
		  answer = [];
		  base = new Value(this.variable);
		  if ((name = base.properties.pop()) && base.isComplex()) {
			ref = o.scope.freeVariable('ref');
			answer = answer.concat(this.makeCode("(" + ref + " = "), base.compileToFragments(o, LEVEL_LIST), this.makeCode(")"), name.compileToFragments(o));
		  } else {
			fun = base.compileToFragments(o, LEVEL_ACCESS);
			if (SIMPLENUM.test(fragmentsToText(fun))) {
			  fun = this.wrapInBraces(fun);
			}
			if (name) {
			  ref = fragmentsToText(fun);
			  fun.push.apply(fun, name.compileToFragments(o));
			} else {
			  ref = 'null';
			}
			answer = answer.concat(fun);
		  }
		  return answer = answer.concat(this.makeCode(".apply(" + ref + ", "), splatArgs, this.makeCode(")"));
		};

		return Call;

	  })(Base);

	  exports.Extends = Extends = (function(superClass1) {
		extend1(Extends, superClass1);

		function Extends(child1, parent1) {
		  this.child = child1;
		  this.parent = parent1;
		}

		Extends.prototype.children = ['child', 'parent'];

		Extends.prototype.compileToFragments = function(o) {
		  return new Call(new Value(new Literal(utility('extend', o))), [this.child, this.parent]).compileToFragments(o);
		};

		return Extends;

	  })(Base);

	  exports.Access = Access = (function(superClass1) {
		extend1(Access, superClass1);

		function Access(name1, tag) {
		  this.name = name1;
		  this.name.asKey = true;
		  this.soak = tag === 'soak';
		}

		Access.prototype.children = ['name'];

		Access.prototype.compileToFragments = function(o) {
		  var name;
		  name = this.name.compileToFragments(o);
		  if (IDENTIFIER.test(fragmentsToText(name))) {
			name.unshift(this.makeCode("."));
		  } else {
			name.unshift(this.makeCode("["));
			name.push(this.makeCode("]"));
		  }
		  return name;
		};

		Access.prototype.isComplex = NO;

		return Access;

	  })(Base);

	  exports.Index = Index = (function(superClass1) {
		extend1(Index, superClass1);

		function Index(index1) {
		  this.index = index1;
		}

		Index.prototype.children = ['index'];

		Index.prototype.compileToFragments = function(o) {
		  return [].concat(this.makeCode("["), this.index.compileToFragments(o, LEVEL_PAREN), this.makeCode("]"));
		};

		Index.prototype.isComplex = function() {
		  return this.index.isComplex();
		};

		return Index;

	  })(Base);

	  exports.Range = Range = (function(superClass1) {
		extend1(Range, superClass1);

		Range.prototype.children = ['from', 'to'];

		function Range(from1, to1, tag) {
		  this.from = from1;
		  this.to = to1;
		  this.exclusive = tag === 'exclusive';
		  this.equals = this.exclusive ? '' : '=';
		}

		Range.prototype.compileVariables = function(o) {
		  var isComplex, ref3, ref4, ref5, ref6, step;
		  o = merge(o, {
			top: true
		  });
		  isComplex = del(o, 'isComplex');
		  ref3 = this.cacheToCodeFragments(this.from.cache(o, LEVEL_LIST, isComplex)), this.fromC = ref3[0], this.fromVar = ref3[1];
		  ref4 = this.cacheToCodeFragments(this.to.cache(o, LEVEL_LIST, isComplex)), this.toC = ref4[0], this.toVar = ref4[1];
		  if (step = del(o, 'step')) {
			ref5 = this.cacheToCodeFragments(step.cache(o, LEVEL_LIST, isComplex)), this.step = ref5[0], this.stepVar = ref5[1];
		  }
		  ref6 = [this.fromVar.match(NUMBER), this.toVar.match(NUMBER)], this.fromNum = ref6[0], this.toNum = ref6[1];
		  if (this.stepVar) {
			return this.stepNum = this.stepVar.match(NUMBER);
		  }
		};

		Range.prototype.compileNode = function(o) {
		  var cond, condPart, from, gt, idx, idxName, known, lt, namedIndex, ref3, ref4, stepPart, to, varPart;
		  if (!this.fromVar) {
			this.compileVariables(o);
		  }
		  if (!o.index) {
			return this.compileArray(o);
		  }
		  known = this.fromNum && this.toNum;
		  idx = del(o, 'index');
		  idxName = del(o, 'name');
		  namedIndex = idxName && idxName !== idx;
		  varPart = idx + " = " + this.fromC;
		  if (this.toC !== this.toVar) {
			varPart += ", " + this.toC;
		  }
		  if (this.step !== this.stepVar) {
			varPart += ", " + this.step;
		  }
		  ref3 = [idx + " <" + this.equals, idx + " >" + this.equals], lt = ref3[0], gt = ref3[1];
		  condPart = this.stepNum ? parseNum(this.stepNum[0]) > 0 ? lt + " " + this.toVar : gt + " " + this.toVar : known ? ((ref4 = [parseNum(this.fromNum[0]), parseNum(this.toNum[0])], from = ref4[0], to = ref4[1], ref4), from <= to ? lt + " " + to : gt + " " + to) : (cond = this.stepVar ? this.stepVar + " > 0" : this.fromVar + " <= " + this.toVar, cond + " ? " + lt + " " + this.toVar + " : " + gt + " " + this.toVar);
		  stepPart = this.stepVar ? idx + " += " + this.stepVar : known ? namedIndex ? from <= to ? "++" + idx : "--" + idx : from <= to ? idx + "++" : idx + "--" : namedIndex ? cond + " ? ++" + idx + " : --" + idx : cond + " ? " + idx + "++ : " + idx + "--";
		  if (namedIndex) {
			varPart = idxName + " = " + varPart;
		  }
		  if (namedIndex) {
			stepPart = idxName + " = " + stepPart;
		  }
		  return [this.makeCode(varPart + "; " + condPart + "; " + stepPart)];
		};

		Range.prototype.compileArray = function(o) {
		  var args, body, cond, hasArgs, i, idt, j, post, pre, range, ref3, ref4, result, results, vars;
		  if (this.fromNum && this.toNum && Math.abs(this.fromNum - this.toNum) <= 20) {
			range = (function() {
			  results = [];
			  for (var j = ref3 = +this.fromNum, ref4 = +this.toNum; ref3 <= ref4 ? j <= ref4 : j >= ref4; ref3 <= ref4 ? j++ : j--){ results.push(j); }
			  return results;
			}).apply(this);
			if (this.exclusive) {
			  range.pop();
			}
			return [this.makeCode("[" + (range.join(', ')) + "]")];
		  }
		  idt = this.tab + TAB;
		  i = o.scope.freeVariable('i', {
			single: true
		  });
		  result = o.scope.freeVariable('results');
		  pre = "\n" + idt + result + " = [];";
		  if (this.fromNum && this.toNum) {
			o.index = i;
			body = fragmentsToText(this.compileNode(o));
		  } else {
			vars = (i + " = " + this.fromC) + (this.toC !== this.toVar ? ", " + this.toC : '');
			cond = this.fromVar + " <= " + this.toVar;
			body = "var " + vars + "; " + cond + " ? " + i + " <" + this.equals + " " + this.toVar + " : " + i + " >" + this.equals + " " + this.toVar + "; " + cond + " ? " + i + "++ : " + i + "--";
		  }
		  post = "{ " + result + ".push(" + i + "); }\n" + idt + "return " + result + ";\n" + o.indent;
		  hasArgs = function(node) {
			return node != null ? node.contains(isLiteralArguments) : void 0;
		  };
		  if (hasArgs(this.from) || hasArgs(this.to)) {
			args = ', arguments';
		  }
		  return [this.makeCode("(function() {" + pre + "\n" + idt + "for (" + body + ")" + post + "}).apply(this" + (args != null ? args : '') + ")")];
		};

		return Range;

	  })(Base);

	  exports.Slice = Slice = (function(superClass1) {
		extend1(Slice, superClass1);

		Slice.prototype.children = ['range'];

		function Slice(range1) {
		  this.range = range1;
		  Slice.__super__.constructor.call(this);
		}

		Slice.prototype.compileNode = function(o) {
		  var compiled, compiledText, from, fromCompiled, ref3, to, toStr;
		  ref3 = this.range, to = ref3.to, from = ref3.from;
		  fromCompiled = from && from.compileToFragments(o, LEVEL_PAREN) || [this.makeCode('0')];
		  if (to) {
			compiled = to.compileToFragments(o, LEVEL_PAREN);
			compiledText = fragmentsToText(compiled);
			if (!(!this.range.exclusive && +compiledText === -1)) {
			  toStr = ', ' + (this.range.exclusive ? compiledText : SIMPLENUM.test(compiledText) ? "" + (+compiledText + 1) : (compiled = to.compileToFragments(o, LEVEL_ACCESS), "+" + (fragmentsToText(compiled)) + " + 1 || 9e9"));
			}
		  }
		  return [this.makeCode(".slice(" + (fragmentsToText(fromCompiled)) + (toStr || '') + ")")];
		};

		return Slice;

	  })(Base);

	  exports.Obj = Obj = (function(superClass1) {
		extend1(Obj, superClass1);

		function Obj(props, generated) {
		  this.generated = generated != null ? generated : false;
		  this.objects = this.properties = props || [];
		}

		Obj.prototype.children = ['properties'];

		Obj.prototype.compileNode = function(o) {
		  var answer, dynamicIndex, hasDynamic, i, idt, indent, j, join, k, key, l, lastNoncom, len1, len2, len3, node, oref, prop, props, ref3, value;
		  props = this.properties;
		  if (this.generated) {
			for (j = 0, len1 = props.length; j < len1; j++) {
			  node = props[j];
			  if (node instanceof Value) {
				node.error('cannot have an implicit value in an implicit object');
			  }
			}
		  }
		  for (dynamicIndex = k = 0, len2 = props.length; k < len2; dynamicIndex = ++k) {
			prop = props[dynamicIndex];
			if ((prop.variable || prop).base instanceof Parens) {
			  break;
			}
		  }
		  hasDynamic = dynamicIndex < props.length;
		  idt = o.indent += TAB;
		  lastNoncom = this.lastNonComment(this.properties);
		  answer = [];
		  if (hasDynamic) {
			oref = o.scope.freeVariable('obj');
			answer.push(this.makeCode("(\n" + idt + oref + " = "));
		  }
		  answer.push(this.makeCode("{" + (props.length === 0 || dynamicIndex === 0 ? '}' : '\n')));
		  for (i = l = 0, len3 = props.length; l < len3; i = ++l) {
			prop = props[i];
			if (i === dynamicIndex) {
			  if (i !== 0) {
				answer.push(this.makeCode("\n" + idt + "}"));
			  }
			  answer.push(this.makeCode(',\n'));
			}
			join = i === props.length - 1 || i === dynamicIndex - 1 ? '' : prop === lastNoncom || prop instanceof Comment ? '\n' : ',\n';
			indent = prop instanceof Comment ? '' : idt;
			if (hasDynamic && i < dynamicIndex) {
			  indent += TAB;
			}
			if (prop instanceof Assign && prop.variable instanceof Value && prop.variable.hasProperties()) {
			  prop.variable.error('Invalid object key');
			}
			if (prop instanceof Value && prop["this"]) {
			  prop = new Assign(prop.properties[0].name, prop, 'object');
			}
			if (!(prop instanceof Comment)) {
			  if (i < dynamicIndex) {
				if (!(prop instanceof Assign)) {
				  prop = new Assign(prop, prop, 'object');
				}
				(prop.variable.base || prop.variable).asKey = true;
			  } else {
				if (prop instanceof Assign) {
				  key = prop.variable;
				  value = prop.value;
				} else {
				  ref3 = prop.base.cache(o), key = ref3[0], value = ref3[1];
				}
				prop = new Assign(new Value(new Literal(oref), [new Access(key)]), value);
			  }
			}
			if (indent) {
			  answer.push(this.makeCode(indent));
			}
			answer.push.apply(answer, prop.compileToFragments(o, LEVEL_TOP));
			if (join) {
			  answer.push(this.makeCode(join));
			}
		  }
		  if (hasDynamic) {
			answer.push(this.makeCode(",\n" + idt + oref + "\n" + this.tab + ")"));
		  } else {
			if (props.length !== 0) {
			  answer.push(this.makeCode("\n" + this.tab + "}"));
			}
		  }
		  if (this.front && !hasDynamic) {
			return this.wrapInBraces(answer);
		  } else {
			return answer;
		  }
		};

		Obj.prototype.assigns = function(name) {
		  var j, len1, prop, ref3;
		  ref3 = this.properties;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			prop = ref3[j];
			if (prop.assigns(name)) {
			  return true;
			}
		  }
		  return false;
		};

		return Obj;

	  })(Base);

	  exports.Arr = Arr = (function(superClass1) {
		extend1(Arr, superClass1);

		function Arr(objs) {
		  this.objects = objs || [];
		}

		Arr.prototype.children = ['objects'];

		Arr.prototype.compileNode = function(o) {
		  var answer, compiledObjs, fragments, index, j, len1, obj;
		  if (!this.objects.length) {
			return [this.makeCode('[]')];
		  }
		  o.indent += TAB;
		  answer = Splat.compileSplattedArray(o, this.objects);
		  if (answer.length) {
			return answer;
		  }
		  answer = [];
		  compiledObjs = (function() {
			var j, len1, ref3, results;
			ref3 = this.objects;
			results = [];
			for (j = 0, len1 = ref3.length; j < len1; j++) {
			  obj = ref3[j];
			  results.push(obj.compileToFragments(o, LEVEL_LIST));
			}
			return results;
		  }).call(this);
		  for (index = j = 0, len1 = compiledObjs.length; j < len1; index = ++j) {
			fragments = compiledObjs[index];
			if (index) {
			  answer.push(this.makeCode(", "));
			}
			answer.push.apply(answer, fragments);
		  }
		  if (fragmentsToText(answer).indexOf('\n') >= 0) {
			answer.unshift(this.makeCode("[\n" + o.indent));
			answer.push(this.makeCode("\n" + this.tab + "]"));
		  } else {
			answer.unshift(this.makeCode("["));
			answer.push(this.makeCode("]"));
		  }
		  return answer;
		};

		Arr.prototype.assigns = function(name) {
		  var j, len1, obj, ref3;
		  ref3 = this.objects;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			obj = ref3[j];
			if (obj.assigns(name)) {
			  return true;
			}
		  }
		  return false;
		};

		return Arr;

	  })(Base);

	  exports.Class = Class = (function(superClass1) {
		extend1(Class, superClass1);

		function Class(variable1, parent1, body1) {
		  this.variable = variable1;
		  this.parent = parent1;
		  this.body = body1 != null ? body1 : new Block;
		  this.boundFuncs = [];
		  this.body.classBody = true;
		}

		Class.prototype.children = ['variable', 'parent', 'body'];

		Class.prototype.determineName = function() {
		  var decl, ref3, tail;
		  if (!this.variable) {
			return null;
		  }
		  ref3 = this.variable.properties, tail = ref3[ref3.length - 1];
		  decl = tail ? tail instanceof Access && tail.name.value : this.variable.base.value;
		  if (indexOf.call(STRICT_PROSCRIBED, decl) >= 0) {
			this.variable.error("class variable name may not be " + decl);
		  }
		  return decl && (decl = IDENTIFIER.test(decl) && decl);
		};

		Class.prototype.setContext = function(name) {
		  return this.body.traverseChildren(false, function(node) {
			if (node.classBody) {
			  return false;
			}
			if (node instanceof Literal && node.value === 'this') {
			  return node.value = name;
			} else if (node instanceof Code) {
			  if (node.bound) {
				return node.context = name;
			  }
			}
		  });
		};

		Class.prototype.addBoundFunctions = function(o) {
		  var bvar, j, len1, lhs, ref3;
		  ref3 = this.boundFuncs;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			bvar = ref3[j];
			lhs = (new Value(new Literal("this"), [new Access(bvar)])).compile(o);
			this.ctor.body.unshift(new Literal(lhs + " = " + (utility('bind', o)) + "(" + lhs + ", this)"));
		  }
		};

		Class.prototype.addProperties = function(node, name, o) {
		  var acc, assign, base, exprs, func, props;
		  props = node.base.properties.slice(0);
		  exprs = (function() {
			var results;
			results = [];
			while (assign = props.shift()) {
			  if (assign instanceof Assign) {
				base = assign.variable.base;
				delete assign.context;
				func = assign.value;
				if (base.value === 'constructor') {
				  if (this.ctor) {
					assign.error('cannot define more than one constructor in a class');
				  }
				  if (func.bound) {
					assign.error('cannot define a constructor as a bound function');
				  }
				  if (func instanceof Code) {
					assign = this.ctor = func;
				  } else {
					this.externalCtor = o.classScope.freeVariable('class');
					assign = new Assign(new Literal(this.externalCtor), func);
				  }
				} else {
				  if (assign.variable["this"]) {
					func["static"] = true;
				  } else {
					acc = base.isComplex() ? new Index(base) : new Access(base);
					assign.variable = new Value(new Literal(name), [new Access(new Literal('prototype')), acc]);
					if (func instanceof Code && func.bound) {
					  this.boundFuncs.push(base);
					  func.bound = false;
					}
				  }
				}
			  }
			  results.push(assign);
			}
			return results;
		  }).call(this);
		  return compact(exprs);
		};

		Class.prototype.walkBody = function(name, o) {
		  return this.traverseChildren(false, (function(_this) {
			return function(child) {
			  var cont, exps, i, j, len1, node, ref3;
			  cont = true;
			  if (child instanceof Class) {
				return false;
			  }
			  if (child instanceof Block) {
				ref3 = exps = child.expressions;
				for (i = j = 0, len1 = ref3.length; j < len1; i = ++j) {
				  node = ref3[i];
				  if (node instanceof Assign && node.variable.looksStatic(name)) {
					node.value["static"] = true;
				  } else if (node instanceof Value && node.isObject(true)) {
					cont = false;
					exps[i] = _this.addProperties(node, name, o);
				  }
				}
				child.expressions = exps = flatten(exps);
			  }
			  return cont && !(child instanceof Class);
			};
		  })(this));
		};

		Class.prototype.hoistDirectivePrologue = function() {
		  var expressions, index, node;
		  index = 0;
		  expressions = this.body.expressions;
		  while ((node = expressions[index]) && node instanceof Comment || node instanceof Value && node.isString()) {
			++index;
		  }
		  return this.directives = expressions.splice(0, index);
		};

		Class.prototype.ensureConstructor = function(name) {
		  if (!this.ctor) {
			this.ctor = new Code;
			if (this.externalCtor) {
			  this.ctor.body.push(new Literal(this.externalCtor + ".apply(this, arguments)"));
			} else if (this.parent) {
			  this.ctor.body.push(new Literal(name + ".__super__.constructor.apply(this, arguments)"));
			}
			this.ctor.body.makeReturn();
			this.body.expressions.unshift(this.ctor);
		  }
		  this.ctor.ctor = this.ctor.name = name;
		  this.ctor.klass = null;
		  return this.ctor.noReturn = true;
		};

		Class.prototype.compileNode = function(o) {
		  var args, argumentsNode, func, jumpNode, klass, lname, name, ref3, superClass;
		  if (jumpNode = this.body.jumps()) {
			jumpNode.error('Class bodies cannot contain pure statements');
		  }
		  if (argumentsNode = this.body.contains(isLiteralArguments)) {
			argumentsNode.error("Class bodies shouldn't reference arguments");
		  }
		  name = this.determineName() || '_Class';
		  if (name.reserved) {
			name = "_" + name;
		  }
		  lname = new Literal(name);
		  func = new Code([], Block.wrap([this.body]));
		  args = [];
		  o.classScope = func.makeScope(o.scope);
		  this.hoistDirectivePrologue();
		  this.setContext(name);
		  this.walkBody(name, o);
		  this.ensureConstructor(name);
		  this.addBoundFunctions(o);
		  this.body.spaced = true;
		  this.body.expressions.push(lname);
		  if (this.parent) {
			superClass = new Literal(o.classScope.freeVariable('superClass', {
			  reserve: false
			}));
			this.body.expressions.unshift(new Extends(lname, superClass));
			func.params.push(new Param(superClass));
			args.push(this.parent);
		  }
		  (ref3 = this.body.expressions).unshift.apply(ref3, this.directives);
		  klass = new Parens(new Call(func, args));
		  if (this.variable) {
			klass = new Assign(this.variable, klass);
		  }
		  return klass.compileToFragments(o);
		};

		return Class;

	  })(Base);

	  exports.Assign = Assign = (function(superClass1) {
		extend1(Assign, superClass1);

		function Assign(variable1, value1, context, options) {
		  var forbidden, name, ref3;
		  this.variable = variable1;
		  this.value = value1;
		  this.context = context;
		  this.param = options && options.param;
		  this.subpattern = options && options.subpattern;
		  forbidden = (ref3 = (name = this.variable.unwrapAll().value), indexOf.call(STRICT_PROSCRIBED, ref3) >= 0);
		  if (forbidden && this.context !== 'object') {
			this.variable.error("variable name may not be \"" + name + "\"");
		  }
		}

		Assign.prototype.children = ['variable', 'value'];

		Assign.prototype.isStatement = function(o) {
		  return (o != null ? o.level : void 0) === LEVEL_TOP && (this.context != null) && indexOf.call(this.context, "?") >= 0;
		};

		Assign.prototype.assigns = function(name) {
		  return this[this.context === 'object' ? 'value' : 'variable'].assigns(name);
		};

		Assign.prototype.unfoldSoak = function(o) {
		  return unfoldSoak(o, this, 'variable');
		};

		Assign.prototype.compileNode = function(o) {
		  var answer, compiledName, isValue, j, name, properties, prototype, ref3, ref4, ref5, ref6, ref7, val, varBase;
		  if (isValue = this.variable instanceof Value) {
			if (this.variable.isArray() || this.variable.isObject()) {
			  return this.compilePatternMatch(o);
			}
			if (this.variable.isSplice()) {
			  return this.compileSplice(o);
			}
			if ((ref3 = this.context) === '||=' || ref3 === '&&=' || ref3 === '?=') {
			  return this.compileConditional(o);
			}
			if ((ref4 = this.context) === '**=' || ref4 === '//=' || ref4 === '%%=') {
			  return this.compileSpecialMath(o);
			}
		  }
		  if (this.value instanceof Code) {
			if (this.value["static"]) {
			  this.value.klass = this.variable.base;
			  this.value.name = this.variable.properties[0];
			  this.value.variable = this.variable;
			} else if (((ref5 = this.variable.properties) != null ? ref5.length : void 0) >= 2) {
			  ref6 = this.variable.properties, properties = 3 <= ref6.length ? slice.call(ref6, 0, j = ref6.length - 2) : (j = 0, []), prototype = ref6[j++], name = ref6[j++];
			  if (((ref7 = prototype.name) != null ? ref7.value : void 0) === 'prototype') {
				this.value.klass = new Value(this.variable.base, properties);
				this.value.name = name;
				this.value.variable = this.variable;
			  }
			}
		  }
		  if (!this.context) {
			varBase = this.variable.unwrapAll();
			if (!varBase.isAssignable()) {
			  this.variable.error("\"" + (this.variable.compile(o)) + "\" cannot be assigned");
			}
			if (!(typeof varBase.hasProperties === "function" ? varBase.hasProperties() : void 0)) {
			  if (this.param) {
				o.scope.add(varBase.value, 'var');
			  } else {
				o.scope.find(varBase.value);
			  }
			}
		  }
		  val = this.value.compileToFragments(o, LEVEL_LIST);
		  compiledName = this.variable.compileToFragments(o, LEVEL_LIST);
		  if (this.context === 'object') {
			return compiledName.concat(this.makeCode(": "), val);
		  }
		  answer = compiledName.concat(this.makeCode(" " + (this.context || '=') + " "), val);
		  if (o.level <= LEVEL_LIST) {
			return answer;
		  } else {
			return this.wrapInBraces(answer);
		  }
		};

		Assign.prototype.compilePatternMatch = function(o) {
		  var acc, assigns, code, expandedIdx, fragments, i, idx, isObject, ivar, j, len1, name, obj, objects, olen, ref, ref3, ref4, ref5, ref6, ref7, ref8, rest, top, val, value, vvar, vvarText;
		  top = o.level === LEVEL_TOP;
		  value = this.value;
		  objects = this.variable.base.objects;
		  if (!(olen = objects.length)) {
			code = value.compileToFragments(o);
			if (o.level >= LEVEL_OP) {
			  return this.wrapInBraces(code);
			} else {
			  return code;
			}
		  }
		  isObject = this.variable.isObject();
		  if (top && olen === 1 && !((obj = objects[0]) instanceof Splat)) {
			if (obj instanceof Assign) {
			  ref3 = obj, (ref4 = ref3.variable, idx = ref4.base), obj = ref3.value;
			} else {
			  idx = isObject ? obj["this"] ? obj.properties[0].name : obj : new Literal(0);
			}
			acc = IDENTIFIER.test(idx.unwrap().value || 0);
			value = new Value(value);
			value.properties.push(new (acc ? Access : Index)(idx));
			if (ref5 = obj.unwrap().value, indexOf.call(RESERVED, ref5) >= 0) {
			  obj.error("assignment to a reserved word: " + (obj.compile(o)));
			}
			return new Assign(obj, value, null, {
			  param: this.param
			}).compileToFragments(o, LEVEL_TOP);
		  }
		  vvar = value.compileToFragments(o, LEVEL_LIST);
		  vvarText = fragmentsToText(vvar);
		  assigns = [];
		  expandedIdx = false;
		  if (!IDENTIFIER.test(vvarText) || this.variable.assigns(vvarText)) {
			assigns.push([this.makeCode((ref = o.scope.freeVariable('ref')) + " = ")].concat(slice.call(vvar)));
			vvar = [this.makeCode(ref)];
			vvarText = ref;
		  }
		  for (i = j = 0, len1 = objects.length; j < len1; i = ++j) {
			obj = objects[i];
			idx = i;
			if (isObject) {
			  if (obj instanceof Assign) {
				ref6 = obj, (ref7 = ref6.variable, idx = ref7.base), obj = ref6.value;
			  } else {
				if (obj.base instanceof Parens) {
				  ref8 = new Value(obj.unwrapAll()).cacheReference(o), obj = ref8[0], idx = ref8[1];
				} else {
				  idx = obj["this"] ? obj.properties[0].name : obj;
				}
			  }
			}
			if (!expandedIdx && obj instanceof Splat) {
			  name = obj.name.unwrap().value;
			  obj = obj.unwrap();
			  val = olen + " <= " + vvarText + ".length ? " + (utility('slice', o)) + ".call(" + vvarText + ", " + i;
			  if (rest = olen - i - 1) {
				ivar = o.scope.freeVariable('i', {
				  single: true
				});
				val += ", " + ivar + " = " + vvarText + ".length - " + rest + ") : (" + ivar + " = " + i + ", [])";
			  } else {
				val += ") : []";
			  }
			  val = new Literal(val);
			  expandedIdx = ivar + "++";
			} else if (!expandedIdx && obj instanceof Expansion) {
			  if (rest = olen - i - 1) {
				if (rest === 1) {
				  expandedIdx = vvarText + ".length - 1";
				} else {
				  ivar = o.scope.freeVariable('i', {
					single: true
				  });
				  val = new Literal(ivar + " = " + vvarText + ".length - " + rest);
				  expandedIdx = ivar + "++";
				  assigns.push(val.compileToFragments(o, LEVEL_LIST));
				}
			  }
			  continue;
			} else {
			  name = obj.unwrap().value;
			  if (obj instanceof Splat || obj instanceof Expansion) {
				obj.error("multiple splats/expansions are disallowed in an assignment");
			  }
			  if (typeof idx === 'number') {
				idx = new Literal(expandedIdx || idx);
				acc = false;
			  } else {
				acc = isObject && IDENTIFIER.test(idx.unwrap().value || 0);
			  }
			  val = new Value(new Literal(vvarText), [new (acc ? Access : Index)(idx)]);
			}
			if ((name != null) && indexOf.call(RESERVED, name) >= 0) {
			  obj.error("assignment to a reserved word: " + (obj.compile(o)));
			}
			assigns.push(new Assign(obj, val, null, {
			  param: this.param,
			  subpattern: true
			}).compileToFragments(o, LEVEL_LIST));
		  }
		  if (!(top || this.subpattern)) {
			assigns.push(vvar);
		  }
		  fragments = this.joinFragmentArrays(assigns, ', ');
		  if (o.level < LEVEL_LIST) {
			return fragments;
		  } else {
			return this.wrapInBraces(fragments);
		  }
		};

		Assign.prototype.compileConditional = function(o) {
		  var fragments, left, ref3, right;
		  ref3 = this.variable.cacheReference(o), left = ref3[0], right = ref3[1];
		  if (!left.properties.length && left.base instanceof Literal && left.base.value !== "this" && !o.scope.check(left.base.value)) {
			this.variable.error("the variable \"" + left.base.value + "\" can't be assigned with " + this.context + " because it has not been declared before");
		  }
		  if (indexOf.call(this.context, "?") >= 0) {
			o.isExistentialEquals = true;
			return new If(new Existence(left), right, {
			  type: 'if'
			}).addElse(new Assign(right, this.value, '=')).compileToFragments(o);
		  } else {
			fragments = new Op(this.context.slice(0, -1), left, new Assign(right, this.value, '=')).compileToFragments(o);
			if (o.level <= LEVEL_LIST) {
			  return fragments;
			} else {
			  return this.wrapInBraces(fragments);
			}
		  }
		};

		Assign.prototype.compileSpecialMath = function(o) {
		  var left, ref3, right;
		  ref3 = this.variable.cacheReference(o), left = ref3[0], right = ref3[1];
		  return new Assign(left, new Op(this.context.slice(0, -1), right, this.value)).compileToFragments(o);
		};

		Assign.prototype.compileSplice = function(o) {
		  var answer, exclusive, from, fromDecl, fromRef, name, ref3, ref4, ref5, to, valDef, valRef;
		  ref3 = this.variable.properties.pop().range, from = ref3.from, to = ref3.to, exclusive = ref3.exclusive;
		  name = this.variable.compile(o);
		  if (from) {
			ref4 = this.cacheToCodeFragments(from.cache(o, LEVEL_OP)), fromDecl = ref4[0], fromRef = ref4[1];
		  } else {
			fromDecl = fromRef = '0';
		  }
		  if (to) {
			if (from instanceof Value && from.isSimpleNumber() && to instanceof Value && to.isSimpleNumber()) {
			  to = to.compile(o) - fromRef;
			  if (!exclusive) {
				to += 1;
			  }
			} else {
			  to = to.compile(o, LEVEL_ACCESS) + ' - ' + fromRef;
			  if (!exclusive) {
				to += ' + 1';
			  }
			}
		  } else {
			to = "9e9";
		  }
		  ref5 = this.value.cache(o, LEVEL_LIST), valDef = ref5[0], valRef = ref5[1];
		  answer = [].concat(this.makeCode("[].splice.apply(" + name + ", [" + fromDecl + ", " + to + "].concat("), valDef, this.makeCode(")), "), valRef);
		  if (o.level > LEVEL_TOP) {
			return this.wrapInBraces(answer);
		  } else {
			return answer;
		  }
		};

		return Assign;

	  })(Base);

	  exports.Code = Code = (function(superClass1) {
		extend1(Code, superClass1);

		function Code(params, body, tag) {
		  this.params = params || [];
		  this.body = body || new Block;
		  this.bound = tag === 'boundfunc';
		  this.isGenerator = !!this.body.contains(function(node) {
			var ref3;
			return node instanceof Op && ((ref3 = node.operator) === 'yield' || ref3 === 'yield*');
		  });
		}

		Code.prototype.children = ['params', 'body'];

		Code.prototype.isStatement = function() {
		  return !!this.ctor;
		};

		Code.prototype.jumps = NO;

		Code.prototype.makeScope = function(parentScope) {
		  return new Scope(parentScope, this.body, this);
		};

		Code.prototype.compileNode = function(o) {
		  var answer, boundfunc, code, exprs, i, j, k, l, len1, len2, len3, len4, len5, len6, lit, m, p, param, params, q, r, ref, ref3, ref4, ref5, ref6, ref7, ref8, splats, uniqs, val, wasEmpty, wrapper;
		  if (this.bound && ((ref3 = o.scope.method) != null ? ref3.bound : void 0)) {
			this.context = o.scope.method.context;
		  }
		  if (this.bound && !this.context) {
			this.context = '_this';
			wrapper = new Code([new Param(new Literal(this.context))], new Block([this]));
			boundfunc = new Call(wrapper, [new Literal('this')]);
			boundfunc.updateLocationDataIfMissing(this.locationData);
			return boundfunc.compileNode(o);
		  }
		  o.scope = del(o, 'classScope') || this.makeScope(o.scope);
		  o.scope.shared = del(o, 'sharedScope');
		  o.indent += TAB;
		  delete o.bare;
		  delete o.isExistentialEquals;
		  params = [];
		  exprs = [];
		  ref4 = this.params;
		  for (j = 0, len1 = ref4.length; j < len1; j++) {
			param = ref4[j];
			if (!(param instanceof Expansion)) {
			  o.scope.parameter(param.asReference(o));
			}
		  }
		  ref5 = this.params;
		  for (k = 0, len2 = ref5.length; k < len2; k++) {
			param = ref5[k];
			if (!(param.splat || param instanceof Expansion)) {
			  continue;
			}
			ref6 = this.params;
			for (l = 0, len3 = ref6.length; l < len3; l++) {
			  p = ref6[l];
			  if (!(p instanceof Expansion) && p.name.value) {
				o.scope.add(p.name.value, 'var', true);
			  }
			}
			splats = new Assign(new Value(new Arr((function() {
			  var len4, m, ref7, results;
			  ref7 = this.params;
			  results = [];
			  for (m = 0, len4 = ref7.length; m < len4; m++) {
				p = ref7[m];
				results.push(p.asReference(o));
			  }
			  return results;
			}).call(this))), new Value(new Literal('arguments')));
			break;
		  }
		  ref7 = this.params;
		  for (m = 0, len4 = ref7.length; m < len4; m++) {
			param = ref7[m];
			if (param.isComplex()) {
			  val = ref = param.asReference(o);
			  if (param.value) {
				val = new Op('?', ref, param.value);
			  }
			  exprs.push(new Assign(new Value(param.name), val, '=', {
				param: true
			  }));
			} else {
			  ref = param;
			  if (param.value) {
				lit = new Literal(ref.name.value + ' == null');
				val = new Assign(new Value(param.name), param.value, '=');
				exprs.push(new If(lit, val));
			  }
			}
			if (!splats) {
			  params.push(ref);
			}
		  }
		  wasEmpty = this.body.isEmpty();
		  if (splats) {
			exprs.unshift(splats);
		  }
		  if (exprs.length) {
			(ref8 = this.body.expressions).unshift.apply(ref8, exprs);
		  }
		  for (i = q = 0, len5 = params.length; q < len5; i = ++q) {
			p = params[i];
			params[i] = p.compileToFragments(o);
			o.scope.parameter(fragmentsToText(params[i]));
		  }
		  uniqs = [];
		  this.eachParamName(function(name, node) {
			if (indexOf.call(uniqs, name) >= 0) {
			  node.error("multiple parameters named " + name);
			}
			return uniqs.push(name);
		  });
		  if (!(wasEmpty || this.noReturn)) {
			this.body.makeReturn();
		  }
		  code = 'function';
		  if (this.isGenerator) {
			code += '*';
		  }
		  if (this.ctor) {
			code += ' ' + this.name;
		  }
		  code += '(';
		  answer = [this.makeCode(code)];
		  for (i = r = 0, len6 = params.length; r < len6; i = ++r) {
			p = params[i];
			if (i) {
			  answer.push(this.makeCode(", "));
			}
			answer.push.apply(answer, p);
		  }
		  answer.push(this.makeCode(') {'));
		  if (!this.body.isEmpty()) {
			answer = answer.concat(this.makeCode("\n"), this.body.compileWithDeclarations(o), this.makeCode("\n" + this.tab));
		  }
		  answer.push(this.makeCode('}'));
		  if (this.ctor) {
			return [this.makeCode(this.tab)].concat(slice.call(answer));
		  }
		  if (this.front || (o.level >= LEVEL_ACCESS)) {
			return this.wrapInBraces(answer);
		  } else {
			return answer;
		  }
		};

		Code.prototype.eachParamName = function(iterator) {
		  var j, len1, param, ref3, results;
		  ref3 = this.params;
		  results = [];
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			param = ref3[j];
			results.push(param.eachName(iterator));
		  }
		  return results;
		};

		Code.prototype.traverseChildren = function(crossScope, func) {
		  if (crossScope) {
			return Code.__super__.traverseChildren.call(this, crossScope, func);
		  }
		};

		return Code;

	  })(Base);

	  exports.Param = Param = (function(superClass1) {
		extend1(Param, superClass1);

		function Param(name1, value1, splat) {
		  var name, ref3;
		  this.name = name1;
		  this.value = value1;
		  this.splat = splat;
		  if (ref3 = (name = this.name.unwrapAll().value), indexOf.call(STRICT_PROSCRIBED, ref3) >= 0) {
			this.name.error("parameter name \"" + name + "\" is not allowed");
		  }
		}

		Param.prototype.children = ['name', 'value'];

		Param.prototype.compileToFragments = function(o) {
		  return this.name.compileToFragments(o, LEVEL_LIST);
		};

		Param.prototype.asReference = function(o) {
		  var name, node;
		  if (this.reference) {
			return this.reference;
		  }
		  node = this.name;
		  if (node["this"]) {
			name = node.properties[0].name.value;
			if (name.reserved) {
			  name = "_" + name;
			}
			node = new Literal(o.scope.freeVariable(name));
		  } else if (node.isComplex()) {
			node = new Literal(o.scope.freeVariable('arg'));
		  }
		  node = new Value(node);
		  if (this.splat) {
			node = new Splat(node);
		  }
		  node.updateLocationDataIfMissing(this.locationData);
		  return this.reference = node;
		};

		Param.prototype.isComplex = function() {
		  return this.name.isComplex();
		};

		Param.prototype.eachName = function(iterator, name) {
		  var atParam, j, len1, node, obj, ref3;
		  if (name == null) {
			name = this.name;
		  }
		  atParam = function(obj) {
			return iterator("@" + obj.properties[0].name.value, obj);
		  };
		  if (name instanceof Literal) {
			return iterator(name.value, name);
		  }
		  if (name instanceof Value) {
			return atParam(name);
		  }
		  ref3 = name.objects;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			obj = ref3[j];
			if (obj instanceof Assign) {
			  this.eachName(iterator, obj.value.unwrap());
			} else if (obj instanceof Splat) {
			  node = obj.name.unwrap();
			  iterator(node.value, node);
			} else if (obj instanceof Value) {
			  if (obj.isArray() || obj.isObject()) {
				this.eachName(iterator, obj.base);
			  } else if (obj["this"]) {
				atParam(obj);
			  } else {
				iterator(obj.base.value, obj.base);
			  }
			} else if (!(obj instanceof Expansion)) {
			  obj.error("illegal parameter " + (obj.compile()));
			}
		  }
		};

		return Param;

	  })(Base);

	  exports.Splat = Splat = (function(superClass1) {
		extend1(Splat, superClass1);

		Splat.prototype.children = ['name'];

		Splat.prototype.isAssignable = YES;

		function Splat(name) {
		  this.name = name.compile ? name : new Literal(name);
		}

		Splat.prototype.assigns = function(name) {
		  return this.name.assigns(name);
		};

		Splat.prototype.compileToFragments = function(o) {
		  return this.name.compileToFragments(o);
		};

		Splat.prototype.unwrap = function() {
		  return this.name;
		};

		Splat.compileSplattedArray = function(o, list, apply) {
		  var args, base, compiledNode, concatPart, fragments, i, index, j, last, len1, node;
		  index = -1;
		  while ((node = list[++index]) && !(node instanceof Splat)) {
			continue;
		  }
		  if (index >= list.length) {
			return [];
		  }
		  if (list.length === 1) {
			node = list[0];
			fragments = node.compileToFragments(o, LEVEL_LIST);
			if (apply) {
			  return fragments;
			}
			return [].concat(node.makeCode((utility('slice', o)) + ".call("), fragments, node.makeCode(")"));
		  }
		  args = list.slice(index);
		  for (i = j = 0, len1 = args.length; j < len1; i = ++j) {
			node = args[i];
			compiledNode = node.compileToFragments(o, LEVEL_LIST);
			args[i] = node instanceof Splat ? [].concat(node.makeCode((utility('slice', o)) + ".call("), compiledNode, node.makeCode(")")) : [].concat(node.makeCode("["), compiledNode, node.makeCode("]"));
		  }
		  if (index === 0) {
			node = list[0];
			concatPart = node.joinFragmentArrays(args.slice(1), ', ');
			return args[0].concat(node.makeCode(".concat("), concatPart, node.makeCode(")"));
		  }
		  base = (function() {
			var k, len2, ref3, results;
			ref3 = list.slice(0, index);
			results = [];
			for (k = 0, len2 = ref3.length; k < len2; k++) {
			  node = ref3[k];
			  results.push(node.compileToFragments(o, LEVEL_LIST));
			}
			return results;
		  })();
		  base = list[0].joinFragmentArrays(base, ', ');
		  concatPart = list[index].joinFragmentArrays(args, ', ');
		  last = list[list.length - 1];
		  return [].concat(list[0].makeCode("["), base, list[index].makeCode("].concat("), concatPart, last.makeCode(")"));
		};

		return Splat;

	  })(Base);

	  exports.Expansion = Expansion = (function(superClass1) {
		extend1(Expansion, superClass1);

		function Expansion() {
		  return Expansion.__super__.constructor.apply(this, arguments);
		}

		Expansion.prototype.isComplex = NO;

		Expansion.prototype.compileNode = function(o) {
		  return this.error('Expansion must be used inside a destructuring assignment or parameter list');
		};

		Expansion.prototype.asReference = function(o) {
		  return this;
		};

		Expansion.prototype.eachName = function(iterator) {};

		return Expansion;

	  })(Base);

	  exports.While = While = (function(superClass1) {
		extend1(While, superClass1);

		function While(condition, options) {
		  this.condition = (options != null ? options.invert : void 0) ? condition.invert() : condition;
		  this.guard = options != null ? options.guard : void 0;
		}

		While.prototype.children = ['condition', 'guard', 'body'];

		While.prototype.isStatement = YES;

		While.prototype.makeReturn = function(res) {
		  if (res) {
			return While.__super__.makeReturn.apply(this, arguments);
		  } else {
			this.returns = !this.jumps({
			  loop: true
			});
			return this;
		  }
		};

		While.prototype.addBody = function(body1) {
		  this.body = body1;
		  return this;
		};

		While.prototype.jumps = function() {
		  var expressions, j, jumpNode, len1, node;
		  expressions = this.body.expressions;
		  if (!expressions.length) {
			return false;
		  }
		  for (j = 0, len1 = expressions.length; j < len1; j++) {
			node = expressions[j];
			if (jumpNode = node.jumps({
			  loop: true
			})) {
			  return jumpNode;
			}
		  }
		  return false;
		};

		While.prototype.compileNode = function(o) {
		  var answer, body, rvar, set;
		  o.indent += TAB;
		  set = '';
		  body = this.body;
		  if (body.isEmpty()) {
			body = this.makeCode('');
		  } else {
			if (this.returns) {
			  body.makeReturn(rvar = o.scope.freeVariable('results'));
			  set = "" + this.tab + rvar + " = [];\n";
			}
			if (this.guard) {
			  if (body.expressions.length > 1) {
				body.expressions.unshift(new If((new Parens(this.guard)).invert(), new Literal("continue")));
			  } else {
				if (this.guard) {
				  body = Block.wrap([new If(this.guard, body)]);
				}
			  }
			}
			body = [].concat(this.makeCode("\n"), body.compileToFragments(o, LEVEL_TOP), this.makeCode("\n" + this.tab));
		  }
		  answer = [].concat(this.makeCode(set + this.tab + "while ("), this.condition.compileToFragments(o, LEVEL_PAREN), this.makeCode(") {"), body, this.makeCode("}"));
		  if (this.returns) {
			answer.push(this.makeCode("\n" + this.tab + "return " + rvar + ";"));
		  }
		  return answer;
		};

		return While;

	  })(Base);

	  exports.Op = Op = (function(superClass1) {
		var CONVERSIONS, INVERSIONS;

		extend1(Op, superClass1);

		function Op(op, first, second, flip) {
		  if (op === 'in') {
			return new In(first, second);
		  }
		  if (op === 'do') {
			return this.generateDo(first);
		  }
		  if (op === 'new') {
			if (first instanceof Call && !first["do"] && !first.isNew) {
			  return first.newInstance();
			}
			if (first instanceof Code && first.bound || first["do"]) {
			  first = new Parens(first);
			}
		  }
		  this.operator = CONVERSIONS[op] || op;
		  this.first = first;
		  this.second = second;
		  this.flip = !!flip;
		  return this;
		}

		CONVERSIONS = {
		  '==': '===',
		  '!=': '!==',
		  'of': 'in',
		  'yieldfrom': 'yield*'
		};

		INVERSIONS = {
		  '!==': '===',
		  '===': '!=='
		};

		Op.prototype.children = ['first', 'second'];

		Op.prototype.isSimpleNumber = NO;

		Op.prototype.isYield = function() {
		  var ref3;
		  return (ref3 = this.operator) === 'yield' || ref3 === 'yield*';
		};

		Op.prototype.isYieldReturn = function() {
		  return this.isYield() && this.first instanceof Return;
		};

		Op.prototype.isUnary = function() {
		  return !this.second;
		};

		Op.prototype.isComplex = function() {
		  var ref3;
		  return !(this.isUnary() && ((ref3 = this.operator) === '+' || ref3 === '-') && this.first instanceof Value && this.first.isSimpleNumber());
		};

		Op.prototype.isChainable = function() {
		  var ref3;
		  return (ref3 = this.operator) === '<' || ref3 === '>' || ref3 === '>=' || ref3 === '<=' || ref3 === '===' || ref3 === '!==';
		};

		Op.prototype.invert = function() {
		  var allInvertable, curr, fst, op, ref3;
		  if (this.isChainable() && this.first.isChainable()) {
			allInvertable = true;
			curr = this;
			while (curr && curr.operator) {
			  allInvertable && (allInvertable = curr.operator in INVERSIONS);
			  curr = curr.first;
			}
			if (!allInvertable) {
			  return new Parens(this).invert();
			}
			curr = this;
			while (curr && curr.operator) {
			  curr.invert = !curr.invert;
			  curr.operator = INVERSIONS[curr.operator];
			  curr = curr.first;
			}
			return this;
		  } else if (op = INVERSIONS[this.operator]) {
			this.operator = op;
			if (this.first.unwrap() instanceof Op) {
			  this.first.invert();
			}
			return this;
		  } else if (this.second) {
			return new Parens(this).invert();
		  } else if (this.operator === '!' && (fst = this.first.unwrap()) instanceof Op && ((ref3 = fst.operator) === '!' || ref3 === 'in' || ref3 === 'instanceof')) {
			return fst;
		  } else {
			return new Op('!', this);
		  }
		};

		Op.prototype.unfoldSoak = function(o) {
		  var ref3;
		  return ((ref3 = this.operator) === '++' || ref3 === '--' || ref3 === 'delete') && unfoldSoak(o, this, 'first');
		};

		Op.prototype.generateDo = function(exp) {
		  var call, func, j, len1, param, passedParams, ref, ref3;
		  passedParams = [];
		  func = exp instanceof Assign && (ref = exp.value.unwrap()) instanceof Code ? ref : exp;
		  ref3 = func.params || [];
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			param = ref3[j];
			if (param.value) {
			  passedParams.push(param.value);
			  delete param.value;
			} else {
			  passedParams.push(param);
			}
		  }
		  call = new Call(exp, passedParams);
		  call["do"] = true;
		  return call;
		};

		Op.prototype.compileNode = function(o) {
		  var answer, isChain, lhs, ref3, ref4, rhs;
		  isChain = this.isChainable() && this.first.isChainable();
		  if (!isChain) {
			this.first.front = this.front;
		  }
		  if (this.operator === 'delete' && o.scope.check(this.first.unwrapAll().value)) {
			this.error('delete operand may not be argument or var');
		  }
		  if (((ref3 = this.operator) === '--' || ref3 === '++') && (ref4 = this.first.unwrapAll().value, indexOf.call(STRICT_PROSCRIBED, ref4) >= 0)) {
			this.error("cannot increment/decrement \"" + (this.first.unwrapAll().value) + "\"");
		  }
		  if (this.isYield()) {
			return this.compileYield(o);
		  }
		  if (this.isUnary()) {
			return this.compileUnary(o);
		  }
		  if (isChain) {
			return this.compileChain(o);
		  }
		  switch (this.operator) {
			case '?':
			  return this.compileExistence(o);
			case '**':
			  return this.compilePower(o);
			case '//':
			  return this.compileFloorDivision(o);
			case '%%':
			  return this.compileModulo(o);
			default:
			  lhs = this.first.compileToFragments(o, LEVEL_OP);
			  rhs = this.second.compileToFragments(o, LEVEL_OP);
			  answer = [].concat(lhs, this.makeCode(" " + this.operator + " "), rhs);
			  if (o.level <= LEVEL_OP) {
				return answer;
			  } else {
				return this.wrapInBraces(answer);
			  }
		  }
		};

		Op.prototype.compileChain = function(o) {
		  var fragments, fst, ref3, shared;
		  ref3 = this.first.second.cache(o), this.first.second = ref3[0], shared = ref3[1];
		  fst = this.first.compileToFragments(o, LEVEL_OP);
		  fragments = fst.concat(this.makeCode(" " + (this.invert ? '&&' : '||') + " "), shared.compileToFragments(o), this.makeCode(" " + this.operator + " "), this.second.compileToFragments(o, LEVEL_OP));
		  return this.wrapInBraces(fragments);
		};

		Op.prototype.compileExistence = function(o) {
		  var fst, ref;
		  if (this.first.isComplex()) {
			ref = new Literal(o.scope.freeVariable('ref'));
			fst = new Parens(new Assign(ref, this.first));
		  } else {
			fst = this.first;
			ref = fst;
		  }
		  return new If(new Existence(fst), ref, {
			type: 'if'
		  }).addElse(this.second).compileToFragments(o);
		};

		Op.prototype.compileUnary = function(o) {
		  var op, parts, plusMinus;
		  parts = [];
		  op = this.operator;
		  parts.push([this.makeCode(op)]);
		  if (op === '!' && this.first instanceof Existence) {
			this.first.negated = !this.first.negated;
			return this.first.compileToFragments(o);
		  }
		  if (o.level >= LEVEL_ACCESS) {
			return (new Parens(this)).compileToFragments(o);
		  }
		  plusMinus = op === '+' || op === '-';
		  if ((op === 'new' || op === 'typeof' || op === 'delete') || plusMinus && this.first instanceof Op && this.first.operator === op) {
			parts.push([this.makeCode(' ')]);
		  }
		  if ((plusMinus && this.first instanceof Op) || (op === 'new' && this.first.isStatement(o))) {
			this.first = new Parens(this.first);
		  }
		  parts.push(this.first.compileToFragments(o, LEVEL_OP));
		  if (this.flip) {
			parts.reverse();
		  }
		  return this.joinFragmentArrays(parts, '');
		};

		Op.prototype.compileYield = function(o) {
		  var op, parts;
		  parts = [];
		  op = this.operator;
		  if (o.scope.parent == null) {
			this.error('yield statements must occur within a function generator.');
		  }
		  if (indexOf.call(Object.keys(this.first), 'expression') >= 0 && !(this.first instanceof Throw)) {
			if (this.isYieldReturn()) {
			  parts.push(this.first.compileToFragments(o, LEVEL_TOP));
			} else if (this.first.expression != null) {
			  parts.push(this.first.expression.compileToFragments(o, LEVEL_OP));
			}
		  } else {
			parts.push([this.makeCode("(" + op + " ")]);
			parts.push(this.first.compileToFragments(o, LEVEL_OP));
			parts.push([this.makeCode(")")]);
		  }
		  return this.joinFragmentArrays(parts, '');
		};

		Op.prototype.compilePower = function(o) {
		  var pow;
		  pow = new Value(new Literal('Math'), [new Access(new Literal('pow'))]);
		  return new Call(pow, [this.first, this.second]).compileToFragments(o);
		};

		Op.prototype.compileFloorDivision = function(o) {
		  var div, floor;
		  floor = new Value(new Literal('Math'), [new Access(new Literal('floor'))]);
		  div = new Op('/', this.first, this.second);
		  return new Call(floor, [div]).compileToFragments(o);
		};

		Op.prototype.compileModulo = function(o) {
		  var mod;
		  mod = new Value(new Literal(utility('modulo', o)));
		  return new Call(mod, [this.first, this.second]).compileToFragments(o);
		};

		Op.prototype.toString = function(idt) {
		  return Op.__super__.toString.call(this, idt, this.constructor.name + ' ' + this.operator);
		};

		return Op;

	  })(Base);

	  exports.In = In = (function(superClass1) {
		extend1(In, superClass1);

		function In(object, array) {
		  this.object = object;
		  this.array = array;
		}

		In.prototype.children = ['object', 'array'];

		In.prototype.invert = NEGATE;

		In.prototype.compileNode = function(o) {
		  var hasSplat, j, len1, obj, ref3;
		  if (this.array instanceof Value && this.array.isArray() && this.array.base.objects.length) {
			ref3 = this.array.base.objects;
			for (j = 0, len1 = ref3.length; j < len1; j++) {
			  obj = ref3[j];
			  if (!(obj instanceof Splat)) {
				continue;
			  }
			  hasSplat = true;
			  break;
			}
			if (!hasSplat) {
			  return this.compileOrTest(o);
			}
		  }
		  return this.compileLoopTest(o);
		};

		In.prototype.compileOrTest = function(o) {
		  var cmp, cnj, i, item, j, len1, ref, ref3, ref4, ref5, sub, tests;
		  ref3 = this.object.cache(o, LEVEL_OP), sub = ref3[0], ref = ref3[1];
		  ref4 = this.negated ? [' !== ', ' && '] : [' === ', ' || '], cmp = ref4[0], cnj = ref4[1];
		  tests = [];
		  ref5 = this.array.base.objects;
		  for (i = j = 0, len1 = ref5.length; j < len1; i = ++j) {
			item = ref5[i];
			if (i) {
			  tests.push(this.makeCode(cnj));
			}
			tests = tests.concat((i ? ref : sub), this.makeCode(cmp), item.compileToFragments(o, LEVEL_ACCESS));
		  }
		  if (o.level < LEVEL_OP) {
			return tests;
		  } else {
			return this.wrapInBraces(tests);
		  }
		};

		In.prototype.compileLoopTest = function(o) {
		  var fragments, ref, ref3, sub;
		  ref3 = this.object.cache(o, LEVEL_LIST), sub = ref3[0], ref = ref3[1];
		  fragments = [].concat(this.makeCode(utility('indexOf', o) + ".call("), this.array.compileToFragments(o, LEVEL_LIST), this.makeCode(", "), ref, this.makeCode(") " + (this.negated ? '< 0' : '>= 0')));
		  if (fragmentsToText(sub) === fragmentsToText(ref)) {
			return fragments;
		  }
		  fragments = sub.concat(this.makeCode(', '), fragments);
		  if (o.level < LEVEL_LIST) {
			return fragments;
		  } else {
			return this.wrapInBraces(fragments);
		  }
		};

		In.prototype.toString = function(idt) {
		  return In.__super__.toString.call(this, idt, this.constructor.name + (this.negated ? '!' : ''));
		};

		return In;

	  })(Base);

	  exports.Try = Try = (function(superClass1) {
		extend1(Try, superClass1);

		function Try(attempt, errorVariable, recovery, ensure) {
		  this.attempt = attempt;
		  this.errorVariable = errorVariable;
		  this.recovery = recovery;
		  this.ensure = ensure;
		}

		Try.prototype.children = ['attempt', 'recovery', 'ensure'];

		Try.prototype.isStatement = YES;

		Try.prototype.jumps = function(o) {
		  var ref3;
		  return this.attempt.jumps(o) || ((ref3 = this.recovery) != null ? ref3.jumps(o) : void 0);
		};

		Try.prototype.makeReturn = function(res) {
		  if (this.attempt) {
			this.attempt = this.attempt.makeReturn(res);
		  }
		  if (this.recovery) {
			this.recovery = this.recovery.makeReturn(res);
		  }
		  return this;
		};

		Try.prototype.compileNode = function(o) {
		  var catchPart, ensurePart, placeholder, tryPart;
		  o.indent += TAB;
		  tryPart = this.attempt.compileToFragments(o, LEVEL_TOP);
		  catchPart = this.recovery ? (placeholder = new Literal('_error'), this.errorVariable ? this.recovery.unshift(new Assign(this.errorVariable, placeholder)) : void 0, [].concat(this.makeCode(" catch ("), placeholder.compileToFragments(o), this.makeCode(") {\n"), this.recovery.compileToFragments(o, LEVEL_TOP), this.makeCode("\n" + this.tab + "}"))) : !(this.ensure || this.recovery) ? [this.makeCode(' catch (_error) {}')] : [];
		  ensurePart = this.ensure ? [].concat(this.makeCode(" finally {\n"), this.ensure.compileToFragments(o, LEVEL_TOP), this.makeCode("\n" + this.tab + "}")) : [];
		  return [].concat(this.makeCode(this.tab + "try {\n"), tryPart, this.makeCode("\n" + this.tab + "}"), catchPart, ensurePart);
		};

		return Try;

	  })(Base);

	  exports.Throw = Throw = (function(superClass1) {
		extend1(Throw, superClass1);

		function Throw(expression) {
		  this.expression = expression;
		}

		Throw.prototype.children = ['expression'];

		Throw.prototype.isStatement = YES;

		Throw.prototype.jumps = NO;

		Throw.prototype.makeReturn = THIS;

		Throw.prototype.compileNode = function(o) {
		  return [].concat(this.makeCode(this.tab + "throw "), this.expression.compileToFragments(o), this.makeCode(";"));
		};

		return Throw;

	  })(Base);

	  exports.Existence = Existence = (function(superClass1) {
		extend1(Existence, superClass1);

		function Existence(expression) {
		  this.expression = expression;
		}

		Existence.prototype.children = ['expression'];

		Existence.prototype.invert = NEGATE;

		Existence.prototype.compileNode = function(o) {
		  var cmp, cnj, code, ref3;
		  this.expression.front = this.front;
		  code = this.expression.compile(o, LEVEL_OP);
		  if (IDENTIFIER.test(code) && !o.scope.check(code)) {
			ref3 = this.negated ? ['===', '||'] : ['!==', '&&'], cmp = ref3[0], cnj = ref3[1];
			code = "typeof " + code + " " + cmp + " \"undefined\" " + cnj + " " + code + " " + cmp + " null";
		  } else {
			code = code + " " + (this.negated ? '==' : '!=') + " null";
		  }
		  return [this.makeCode(o.level <= LEVEL_COND ? code : "(" + code + ")")];
		};

		return Existence;

	  })(Base);

	  exports.Parens = Parens = (function(superClass1) {
		extend1(Parens, superClass1);

		function Parens(body1) {
		  this.body = body1;
		}

		Parens.prototype.children = ['body'];

		Parens.prototype.unwrap = function() {
		  return this.body;
		};

		Parens.prototype.isComplex = function() {
		  return this.body.isComplex();
		};

		Parens.prototype.compileNode = function(o) {
		  var bare, expr, fragments;
		  expr = this.body.unwrap();
		  if (expr instanceof Value && expr.isAtomic()) {
			expr.front = this.front;
			return expr.compileToFragments(o);
		  }
		  fragments = expr.compileToFragments(o, LEVEL_PAREN);
		  bare = o.level < LEVEL_OP && (expr instanceof Op || expr instanceof Call || (expr instanceof For && expr.returns));
		  if (bare) {
			return fragments;
		  } else {
			return this.wrapInBraces(fragments);
		  }
		};

		return Parens;

	  })(Base);

	  exports.For = For = (function(superClass1) {
		extend1(For, superClass1);

		function For(body, source) {
		  var ref3;
		  this.source = source.source, this.guard = source.guard, this.step = source.step, this.name = source.name, this.index = source.index;
		  this.body = Block.wrap([body]);
		  this.own = !!source.own;
		  this.object = !!source.object;
		  if (this.object) {
			ref3 = [this.index, this.name], this.name = ref3[0], this.index = ref3[1];
		  }
		  if (this.index instanceof Value) {
			this.index.error('index cannot be a pattern matching expression');
		  }
		  this.range = this.source instanceof Value && this.source.base instanceof Range && !this.source.properties.length;
		  this.pattern = this.name instanceof Value;
		  if (this.range && this.index) {
			this.index.error('indexes do not apply to range loops');
		  }
		  if (this.range && this.pattern) {
			this.name.error('cannot pattern match over range loops');
		  }
		  if (this.own && !this.object) {
			this.name.error('cannot use own with for-in');
		  }
		  this.returns = false;
		}

		For.prototype.children = ['body', 'source', 'guard', 'step'];

		For.prototype.compileNode = function(o) {
		  var body, bodyFragments, compare, compareDown, declare, declareDown, defPart, defPartFragments, down, forPartFragments, guardPart, idt1, increment, index, ivar, kvar, kvarAssign, last, lvar, name, namePart, ref, ref3, ref4, resultPart, returnResult, rvar, scope, source, step, stepNum, stepVar, svar, varPart;
		  body = Block.wrap([this.body]);
		  ref3 = body.expressions, last = ref3[ref3.length - 1];
		  if ((last != null ? last.jumps() : void 0) instanceof Return) {
			this.returns = false;
		  }
		  source = this.range ? this.source.base : this.source;
		  scope = o.scope;
		  if (!this.pattern) {
			name = this.name && (this.name.compile(o, LEVEL_LIST));
		  }
		  index = this.index && (this.index.compile(o, LEVEL_LIST));
		  if (name && !this.pattern) {
			scope.find(name);
		  }
		  if (index) {
			scope.find(index);
		  }
		  if (this.returns) {
			rvar = scope.freeVariable('results');
		  }
		  ivar = (this.object && index) || scope.freeVariable('i', {
			single: true
		  });
		  kvar = (this.range && name) || index || ivar;
		  kvarAssign = kvar !== ivar ? kvar + " = " : "";
		  if (this.step && !this.range) {
			ref4 = this.cacheToCodeFragments(this.step.cache(o, LEVEL_LIST, isComplexOrAssignable)), step = ref4[0], stepVar = ref4[1];
			stepNum = stepVar.match(NUMBER);
		  }
		  if (this.pattern) {
			name = ivar;
		  }
		  varPart = '';
		  guardPart = '';
		  defPart = '';
		  idt1 = this.tab + TAB;
		  if (this.range) {
			forPartFragments = source.compileToFragments(merge(o, {
			  index: ivar,
			  name: name,
			  step: this.step,
			  isComplex: isComplexOrAssignable
			}));
		  } else {
			svar = this.source.compile(o, LEVEL_LIST);
			if ((name || this.own) && !IDENTIFIER.test(svar)) {
			  defPart += "" + this.tab + (ref = scope.freeVariable('ref')) + " = " + svar + ";\n";
			  svar = ref;
			}
			if (name && !this.pattern) {
			  namePart = name + " = " + svar + "[" + kvar + "]";
			}
			if (!this.object) {
			  if (step !== stepVar) {
				defPart += "" + this.tab + step + ";\n";
			  }
			  if (!(this.step && stepNum && (down = parseNum(stepNum[0]) < 0))) {
				lvar = scope.freeVariable('len');
			  }
			  declare = "" + kvarAssign + ivar + " = 0, " + lvar + " = " + svar + ".length";
			  declareDown = "" + kvarAssign + ivar + " = " + svar + ".length - 1";
			  compare = ivar + " < " + lvar;
			  compareDown = ivar + " >= 0";
			  if (this.step) {
				if (stepNum) {
				  if (down) {
					compare = compareDown;
					declare = declareDown;
				  }
				} else {
				  compare = stepVar + " > 0 ? " + compare + " : " + compareDown;
				  declare = "(" + stepVar + " > 0 ? (" + declare + ") : " + declareDown + ")";
				}
				increment = ivar + " += " + stepVar;
			  } else {
				increment = "" + (kvar !== ivar ? "++" + ivar : ivar + "++");
			  }
			  forPartFragments = [this.makeCode(declare + "; " + compare + "; " + kvarAssign + increment)];
			}
		  }
		  if (this.returns) {
			resultPart = "" + this.tab + rvar + " = [];\n";
			returnResult = "\n" + this.tab + "return " + rvar + ";";
			body.makeReturn(rvar);
		  }
		  if (this.guard) {
			if (body.expressions.length > 1) {
			  body.expressions.unshift(new If((new Parens(this.guard)).invert(), new Literal("continue")));
			} else {
			  if (this.guard) {
				body = Block.wrap([new If(this.guard, body)]);
			  }
			}
		  }
		  if (this.pattern) {
			body.expressions.unshift(new Assign(this.name, new Literal(svar + "[" + kvar + "]")));
		  }
		  defPartFragments = [].concat(this.makeCode(defPart), this.pluckDirectCall(o, body));
		  if (namePart) {
			varPart = "\n" + idt1 + namePart + ";";
		  }
		  if (this.object) {
			forPartFragments = [this.makeCode(kvar + " in " + svar)];
			if (this.own) {
			  guardPart = "\n" + idt1 + "if (!" + (utility('hasProp', o)) + ".call(" + svar + ", " + kvar + ")) continue;";
			}
		  }
		  bodyFragments = body.compileToFragments(merge(o, {
			indent: idt1
		  }), LEVEL_TOP);
		  if (bodyFragments && (bodyFragments.length > 0)) {
			bodyFragments = [].concat(this.makeCode("\n"), bodyFragments, this.makeCode("\n"));
		  }
		  return [].concat(defPartFragments, this.makeCode("" + (resultPart || '') + this.tab + "for ("), forPartFragments, this.makeCode(") {" + guardPart + varPart), bodyFragments, this.makeCode(this.tab + "}" + (returnResult || '')));
		};

		For.prototype.pluckDirectCall = function(o, body) {
		  var base, defs, expr, fn, idx, j, len1, ref, ref3, ref4, ref5, ref6, ref7, ref8, ref9, val;
		  defs = [];
		  ref3 = body.expressions;
		  for (idx = j = 0, len1 = ref3.length; j < len1; idx = ++j) {
			expr = ref3[idx];
			expr = expr.unwrapAll();
			if (!(expr instanceof Call)) {
			  continue;
			}
			val = (ref4 = expr.variable) != null ? ref4.unwrapAll() : void 0;
			if (!((val instanceof Code) || (val instanceof Value && ((ref5 = val.base) != null ? ref5.unwrapAll() : void 0) instanceof Code && val.properties.length === 1 && ((ref6 = (ref7 = val.properties[0].name) != null ? ref7.value : void 0) === 'call' || ref6 === 'apply')))) {
			  continue;
			}
			fn = ((ref8 = val.base) != null ? ref8.unwrapAll() : void 0) || val;
			ref = new Literal(o.scope.freeVariable('fn'));
			base = new Value(ref);
			if (val.base) {
			  ref9 = [base, val], val.base = ref9[0], base = ref9[1];
			}
			body.expressions[idx] = new Call(base, expr.args);
			defs = defs.concat(this.makeCode(this.tab), new Assign(ref, fn).compileToFragments(o, LEVEL_TOP), this.makeCode(';\n'));
		  }
		  return defs;
		};

		return For;

	  })(While);

	  exports.Switch = Switch = (function(superClass1) {
		extend1(Switch, superClass1);

		function Switch(subject, cases, otherwise) {
		  this.subject = subject;
		  this.cases = cases;
		  this.otherwise = otherwise;
		}

		Switch.prototype.children = ['subject', 'cases', 'otherwise'];

		Switch.prototype.isStatement = YES;

		Switch.prototype.jumps = function(o) {
		  var block, conds, j, jumpNode, len1, ref3, ref4, ref5;
		  if (o == null) {
			o = {
			  block: true
			};
		  }
		  ref3 = this.cases;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			ref4 = ref3[j], conds = ref4[0], block = ref4[1];
			if (jumpNode = block.jumps(o)) {
			  return jumpNode;
			}
		  }
		  return (ref5 = this.otherwise) != null ? ref5.jumps(o) : void 0;
		};

		Switch.prototype.makeReturn = function(res) {
		  var j, len1, pair, ref3, ref4;
		  ref3 = this.cases;
		  for (j = 0, len1 = ref3.length; j < len1; j++) {
			pair = ref3[j];
			pair[1].makeReturn(res);
		  }
		  if (res) {
			this.otherwise || (this.otherwise = new Block([new Literal('void 0')]));
		  }
		  if ((ref4 = this.otherwise) != null) {
			ref4.makeReturn(res);
		  }
		  return this;
		};

		Switch.prototype.compileNode = function(o) {
		  var block, body, cond, conditions, expr, fragments, i, idt1, idt2, j, k, len1, len2, ref3, ref4, ref5;
		  idt1 = o.indent + TAB;
		  idt2 = o.indent = idt1 + TAB;
		  fragments = [].concat(this.makeCode(this.tab + "switch ("), (this.subject ? this.subject.compileToFragments(o, LEVEL_PAREN) : this.makeCode("false")), this.makeCode(") {\n"));
		  ref3 = this.cases;
		  for (i = j = 0, len1 = ref3.length; j < len1; i = ++j) {
			ref4 = ref3[i], conditions = ref4[0], block = ref4[1];
			ref5 = flatten([conditions]);
			for (k = 0, len2 = ref5.length; k < len2; k++) {
			  cond = ref5[k];
			  if (!this.subject) {
				cond = cond.invert();
			  }
			  fragments = fragments.concat(this.makeCode(idt1 + "case "), cond.compileToFragments(o, LEVEL_PAREN), this.makeCode(":\n"));
			}
			if ((body = block.compileToFragments(o, LEVEL_TOP)).length > 0) {
			  fragments = fragments.concat(body, this.makeCode('\n'));
			}
			if (i === this.cases.length - 1 && !this.otherwise) {
			  break;
			}
			expr = this.lastNonComment(block.expressions);
			if (expr instanceof Return || (expr instanceof Literal && expr.jumps() && expr.value !== 'debugger')) {
			  continue;
			}
			fragments.push(cond.makeCode(idt2 + 'break;\n'));
		  }
		  if (this.otherwise && this.otherwise.expressions.length) {
			fragments.push.apply(fragments, [this.makeCode(idt1 + "default:\n")].concat(slice.call(this.otherwise.compileToFragments(o, LEVEL_TOP)), [this.makeCode("\n")]));
		  }
		  fragments.push(this.makeCode(this.tab + '}'));
		  return fragments;
		};

		return Switch;

	  })(Base);

	  exports.If = If = (function(superClass1) {
		extend1(If, superClass1);

		function If(condition, body1, options) {
		  this.body = body1;
		  if (options == null) {
			options = {};
		  }
		  this.condition = options.type === 'unless' ? condition.invert() : condition;
		  this.elseBody = null;
		  this.isChain = false;
		  this.soak = options.soak;
		}

		If.prototype.children = ['condition', 'body', 'elseBody'];

		If.prototype.bodyNode = function() {
		  var ref3;
		  return (ref3 = this.body) != null ? ref3.unwrap() : void 0;
		};

		If.prototype.elseBodyNode = function() {
		  var ref3;
		  return (ref3 = this.elseBody) != null ? ref3.unwrap() : void 0;
		};

		If.prototype.addElse = function(elseBody) {
		  if (this.isChain) {
			this.elseBodyNode().addElse(elseBody);
		  } else {
			this.isChain = elseBody instanceof If;
			this.elseBody = this.ensureBlock(elseBody);
			this.elseBody.updateLocationDataIfMissing(elseBody.locationData);
		  }
		  return this;
		};

		If.prototype.isStatement = function(o) {
		  var ref3;
		  return (o != null ? o.level : void 0) === LEVEL_TOP || this.bodyNode().isStatement(o) || ((ref3 = this.elseBodyNode()) != null ? ref3.isStatement(o) : void 0);
		};

		If.prototype.jumps = function(o) {
		  var ref3;
		  return this.body.jumps(o) || ((ref3 = this.elseBody) != null ? ref3.jumps(o) : void 0);
		};

		If.prototype.compileNode = function(o) {
		  if (this.isStatement(o)) {
			return this.compileStatement(o);
		  } else {
			return this.compileExpression(o);
		  }
		};

		If.prototype.makeReturn = function(res) {
		  if (res) {
			this.elseBody || (this.elseBody = new Block([new Literal('void 0')]));
		  }
		  this.body && (this.body = new Block([this.body.makeReturn(res)]));
		  this.elseBody && (this.elseBody = new Block([this.elseBody.makeReturn(res)]));
		  return this;
		};

		If.prototype.ensureBlock = function(node) {
		  if (node instanceof Block) {
			return node;
		  } else {
			return new Block([node]);
		  }
		};

		If.prototype.compileStatement = function(o) {
		  var answer, body, child, cond, exeq, ifPart, indent;
		  child = del(o, 'chainChild');
		  exeq = del(o, 'isExistentialEquals');
		  if (exeq) {
			return new If(this.condition.invert(), this.elseBodyNode(), {
			  type: 'if'
			}).compileToFragments(o);
		  }
		  indent = o.indent + TAB;
		  cond = this.condition.compileToFragments(o, LEVEL_PAREN);
		  body = this.ensureBlock(this.body).compileToFragments(merge(o, {
			indent: indent
		  }));
		  ifPart = [].concat(this.makeCode("if ("), cond, this.makeCode(") {\n"), body, this.makeCode("\n" + this.tab + "}"));
		  if (!child) {
			ifPart.unshift(this.makeCode(this.tab));
		  }
		  if (!this.elseBody) {
			return ifPart;
		  }
		  answer = ifPart.concat(this.makeCode(' else '));
		  if (this.isChain) {
			o.chainChild = true;
			answer = answer.concat(this.elseBody.unwrap().compileToFragments(o, LEVEL_TOP));
		  } else {
			answer = answer.concat(this.makeCode("{\n"), this.elseBody.compileToFragments(merge(o, {
			  indent: indent
			}), LEVEL_TOP), this.makeCode("\n" + this.tab + "}"));
		  }
		  return answer;
		};

		If.prototype.compileExpression = function(o) {
		  var alt, body, cond, fragments;
		  cond = this.condition.compileToFragments(o, LEVEL_COND);
		  body = this.bodyNode().compileToFragments(o, LEVEL_LIST);
		  alt = this.elseBodyNode() ? this.elseBodyNode().compileToFragments(o, LEVEL_LIST) : [this.makeCode('void 0')];
		  fragments = cond.concat(this.makeCode(" ? "), body, this.makeCode(" : "), alt);
		  if (o.level >= LEVEL_COND) {
			return this.wrapInBraces(fragments);
		  } else {
			return fragments;
		  }
		};

		If.prototype.unfoldSoak = function() {
		  return this.soak && this;
		};

		return If;

	  })(Base);

	  UTILITIES = {
		extend: function(o) {
		  return "function(child, parent) { for (var key in parent) { if (" + (utility('hasProp', o)) + ".call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; }";
		},
		bind: function() {
		  return 'function(fn, me){ return function(){ return fn.apply(me, arguments); }; }';
		},
		indexOf: function() {
		  return "[].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; }";
		},
		modulo: function() {
		  return "function(a, b) { return (+a % (b = +b) + b) % b; }";
		},
		hasProp: function() {
		  return '{}.hasOwnProperty';
		},
		slice: function() {
		  return '[].slice';
		}
	  };

	  LEVEL_TOP = 1;

	  LEVEL_PAREN = 2;

	  LEVEL_LIST = 3;

	  LEVEL_COND = 4;

	  LEVEL_OP = 5;

	  LEVEL_ACCESS = 6;

	  TAB = '  ';

	  IDENTIFIER = /^(?!\d)[$\w\x7f-\uffff]+$/;

	  SIMPLENUM = /^[+-]?\d+$/;

	  HEXNUM = /^[+-]?0x[\da-f]+/i;

	  NUMBER = /^[+-]?(?:0x[\da-f]+|\d*\.?\d+(?:e[+-]?\d+)?)$/i;

	  IS_STRING = /^['"]/;

	  IS_REGEX = /^\//;

	  utility = function(name, o) {
		var ref, root;
		root = o.scope.root;
		if (name in root.utilities) {
		  return root.utilities[name];
		} else {
		  ref = root.freeVariable(name);
		  root.assign(ref, UTILITIES[name](o));
		  return root.utilities[name] = ref;
		}
	  };

	  multident = function(code, tab) {
		code = code.replace(/\n/g, '$&' + tab);
		return code.replace(/\s+$/, '');
	  };

	  parseNum = function(x) {
		if (x == null) {
		  return 0;
		} else if (x.match(HEXNUM)) {
		  return parseInt(x, 16);
		} else {
		  return parseFloat(x);
		}
	  };

	  isLiteralArguments = function(node) {
		return node instanceof Literal && node.value === 'arguments' && !node.asKey;
	  };

	  isLiteralThis = function(node) {
		return (node instanceof Literal && node.value === 'this' && !node.asKey) || (node instanceof Code && node.bound) || (node instanceof Call && node.isSuper);
	  };

	  isComplexOrAssignable = function(node) {
		return node.isComplex() || (typeof node.isAssignable === "function" ? node.isAssignable() : void 0);
	  };

	  unfoldSoak = function(o, parent, name) {
		var ifn;
		if (!(ifn = parent[name].unfoldSoak(o))) {
		  return;
		}
		parent[name] = ifn.body;
		ifn.body = new Value(parent);
		return ifn;
	  };

	  return exports;
	};
	//#endregion
	
	//#region URL: /coffee-script
	modules['/coffee-script'] = function () {
	  var exports = {};
	  var Lexer, SourceMap, base, compile, ext, formatSourcePosition, fs, getSourceMap, helpers, i, len, lexer, parser, path, ref, sourceMaps, vm, withPrettyErrors,
		hasProp = {}.hasOwnProperty,
		indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

//	  fs = require('fs');

//	  vm = require('vm');

//	  path = require('path');

	  Lexer = require('/lexer').Lexer;

	  parser = require('/parser').parser;

	  helpers = require('/helpers');

//	  SourceMap = require('/sourcemap');

	  exports.VERSION = '1.9.2';

//	  exports.FILE_EXTENSIONS = ['.coffee', '.litcoffee', '.coffee.md'];

	  exports.helpers = helpers;

	  withPrettyErrors = function(fn) {
		return function(code, options) {
		  var err;
		  if (options == null) {
			options = {};
		  }
		  try {
			return fn.call(this, code, options);
		  } catch (_error) {
			err = _error;
			throw helpers.updateSyntaxError(err, code, options.filename);
		  }
		};
	  };

	  exports.compile = compile = withPrettyErrors(function(code, options) {
		var answer, currentColumn, currentLine, extend, fragment, fragments, header, i, js, len, map, merge, newLines, token, tokens;
		merge = helpers.merge, extend = helpers.extend;
		options = extend({}, options);
//		if (options.sourceMap) {
//		  map = new SourceMap;
//		}
		tokens = lexer.tokenize(code, options);
		options.referencedVars = (function() {
		  var i, len, results;
		  results = [];
		  for (i = 0, len = tokens.length; i < len; i++) {
			token = tokens[i];
			if (token.variable) {
			  results.push(token[1]);
			}
		  }
		  return results;
		})();
		fragments = parser.parse(tokens).compileToFragments(options);
		currentLine = 0;
//		if (options.header) {
//		  currentLine += 1;
//		}
//		if (options.shiftLine) {
//		  currentLine += 1;
//		}
		currentColumn = 0;
		js = "";
		for (i = 0, len = fragments.length; i < len; i++) {
		  fragment = fragments[i];
//		  if (options.sourceMap) {
//			if (fragment.locationData) {
//			  map.add([fragment.locationData.first_line, fragment.locationData.first_column], [currentLine, currentColumn], {
//				noReplace: true
//			  });
//			}
//			newLines = helpers.count(fragment.code, "\n");
//			currentLine += newLines;
//			if (newLines) {
//			  currentColumn = fragment.code.length - (fragment.code.lastIndexOf("\n") + 1);
//			} else {
//			  currentColumn += fragment.code.length;
//			}
//		  }
		  js += fragment.code;
		}
//		if (options.header) {
//		  header = "Generated by CoffeeScript " + this.VERSION;
//		  js = "// " + header + "\n" + js;
//		}
//		if (options.sourceMap) {
//		  answer = {
//			js: js
//		  };
//		  answer.sourceMap = map;
//		  answer.v3SourceMap = map.generate(options, code);
//		  return answer;
//		} else {
		  return js;
//		}
	  });

//	  exports.tokens = withPrettyErrors(function(code, options) {
//		return lexer.tokenize(code, options);
//	  });

//	  exports.nodes = withPrettyErrors(function(source, options) {
//		if (typeof source === 'string') {
//		  return parser.parse(lexer.tokenize(source, options));
//		} else {
//		  return parser.parse(source);
//		}
//	  });

//	  exports.run = function(code, options) {
//		var answer, dir, mainModule, ref;
//		if (options == null) {
//		  options = {};
//		}
//		mainModule = require.main;
//		mainModule.filename = process.argv[1] = options.filename ? fs.realpathSync(options.filename) : '.';
//		mainModule.moduleCache && (mainModule.moduleCache = {});
//		dir = options.filename ? path.dirname(fs.realpathSync(options.filename)) : fs.realpathSync('.');
//		mainModule.paths = require('module')._nodeModulePaths(dir);
//		if (!helpers.isCoffee(mainModule.filename) || require.extensions) {
//		  answer = compile(code, options);
//		  code = (ref = answer.js) != null ? ref : answer;
//		}
//		return mainModule._compile(code, mainModule.filename);
//	  };

//	  exports["eval"] = function(code, options) {
//		var Module, _module, _require, createContext, i, isContext, js, k, len, o, r, ref, ref1, ref2, ref3, sandbox, v;
//		if (options == null) {
//		  options = {};
//		}
//		if (!(code = code.trim())) {
//		  return;
//		}
//		createContext = (ref = vm.Script.createContext) != null ? ref : vm.createContext;
//		isContext = (ref1 = vm.isContext) != null ? ref1 : function(ctx) {
//		  return options.sandbox instanceof createContext().constructor;
//		};
//		if (createContext) {
//		  if (options.sandbox != null) {
//			if (isContext(options.sandbox)) {
//			  sandbox = options.sandbox;
//			} else {
//			  sandbox = createContext();
//			  ref2 = options.sandbox;
//			  for (k in ref2) {
//				if (!hasProp.call(ref2, k)) continue;
//				v = ref2[k];
//				sandbox[k] = v;
//			  }
//			}
//			sandbox.global = sandbox.root = sandbox.GLOBAL = sandbox;
//		  } else {
//			sandbox = global;
//		  }
//		  sandbox.__filename = options.filename || 'eval';
//		  sandbox.__dirname = path.dirname(sandbox.__filename);
//		  if (!(sandbox !== global || sandbox.module || sandbox.require)) {
//			Module = require('module');
//			sandbox.module = _module = new Module(options.modulename || 'eval');
//			sandbox.require = _require = function(path) {
//			  return Module._load(path, _module, true);
//			};
//			_module.filename = sandbox.__filename;
//			ref3 = Object.getOwnPropertyNames(require);
//			for (i = 0, len = ref3.length; i < len; i++) {
//			  r = ref3[i];
//			  if (r !== 'paths') {
//				_require[r] = require[r];
//			  }
//			}
//			_require.paths = _module.paths = Module._nodeModulePaths(process.cwd());
//			_require.resolve = function(request) {
//			  return Module._resolveFilename(request, _module);
//			};
//		  }
//		}
//		o = {};
//		for (k in options) {
//		  if (!hasProp.call(options, k)) continue;
//		  v = options[k];
//		  o[k] = v;
//		}
//		o.bare = true;
//		js = compile(code, o);
//		if (sandbox === global) {
//		  return vm.runInThisContext(js);
//		} else {
//		  return vm.runInContext(js, sandbox);
//		}
//	  };

//	  exports.register = function() {
//		return require('/register');
//	  };

//	  if (require.extensions) {
//		ref = this.FILE_EXTENSIONS;
//		for (i = 0, len = ref.length; i < len; i++) {
//		  ext = ref[i];
//		  if ((base = require.extensions)[ext] == null) {
//			base[ext] = function() {
//			  throw new Error("Use CoffeeScript.register() or require the coffee-script/register module to require " + ext + " files.");
//			};
//		  }
//		}
//	  }

//	  exports._compileFile = function(filename, sourceMap) {
//		var answer, err, raw, stripped;
//		if (sourceMap == null) {
//		  sourceMap = false;
//		}
//		raw = fs.readFileSync(filename, 'utf8');
//		stripped = raw.charCodeAt(0) === 0xFEFF ? raw.substring(1) : raw;
//		try {
//		  answer = compile(stripped, {
//			filename: filename,
//			sourceMap: sourceMap,
//			literate: helpers.isLiterate(filename)
//		  });
//		} catch (_error) {
//		  err = _error;
//		  throw helpers.updateSyntaxError(err, stripped, filename);
//		}
//		return answer;
//	  };

	  lexer = new Lexer;

	  parser.lexer = {
		lex: function() {
		  var tag, token;
		  token = parser.tokens[this.pos++];
		  if (token) {
			tag = token[0], this.yytext = token[1], this.yylloc = token[2];
			parser.errorToken = token.origin || token;
			this.yylineno = this.yylloc.first_line;
		  } else {
			tag = '';
		  }
		  return tag;
		},
		setInput: function(tokens) {
		  parser.tokens = tokens;
		  return this.pos = 0;
		},
		upcomingInput: function() {
		  return "";
		}
	  };

	  parser.yy = require('/nodes');

	  parser.yy.parseError = function(message, arg) {
		var errorLoc, errorTag, errorText, errorToken, token, tokens;
		token = arg.token;
		errorToken = parser.errorToken, tokens = parser.tokens;
		errorTag = errorToken[0], errorText = errorToken[1], errorLoc = errorToken[2];
		errorText = (function() {
		  switch (false) {
			case errorToken !== tokens[tokens.length - 1]:
			  return 'end of input';
			case errorTag !== 'INDENT' && errorTag !== 'OUTDENT':
			  return 'indentation';
			case errorTag !== 'IDENTIFIER' && errorTag !== 'NUMBER' && errorTag !== 'STRING' && errorTag !== 'STRING_START' && errorTag !== 'REGEX' && errorTag !== 'REGEX_START':
			  return errorTag.replace(/_START$/, '').toLowerCase();
			default:
			  return helpers.nameWhitespaceCharacter(errorText);
		  }
		})();
		return helpers.throwSyntaxError("unexpected " + errorText, errorLoc);
	  };

//	  formatSourcePosition = function(frame, getSourceMapping) {
//		var as, column, fileLocation, fileName, functionName, isConstructor, isMethodCall, line, methodName, source, tp, typeName;
//		fileName = void 0;
//		fileLocation = '';
//		if (frame.isNative()) {
//		  fileLocation = "native";
//		} else {
//		  if (frame.isEval()) {
//			fileName = frame.getScriptNameOrSourceURL();
//			if (!fileName) {
//			  fileLocation = (frame.getEvalOrigin()) + ", ";
//			}
//		  } else {
//			fileName = frame.getFileName();
//		  }
//		  fileName || (fileName = "<anonymous>");
//		  line = frame.getLineNumber();
//		  column = frame.getColumnNumber();
//		  source = getSourceMapping(fileName, line, column);
//		  fileLocation = source ? fileName + ":" + source[0] + ":" + source[1] : fileName + ":" + line + ":" + column;
//		}
//		functionName = frame.getFunctionName();
//		isConstructor = frame.isConstructor();
//		isMethodCall = !(frame.isToplevel() || isConstructor);
//		if (isMethodCall) {
//		  methodName = frame.getMethodName();
//		  typeName = frame.getTypeName();
//		  if (functionName) {
//			tp = as = '';
//			if (typeName && functionName.indexOf(typeName)) {
//			  tp = typeName + ".";
//			}
//			if (methodName && functionName.indexOf("." + methodName) !== functionName.length - methodName.length - 1) {
//			  as = " [as " + methodName + "]";
//			}
//			return "" + tp + functionName + as + " (" + fileLocation + ")";
//		  } else {
//			return typeName + "." + (methodName || '<anonymous>') + " (" + fileLocation + ")";
//		  }
//		} else if (isConstructor) {
//		  return "new " + (functionName || '<anonymous>') + " (" + fileLocation + ")";
//		} else if (functionName) {
//		  return functionName + " (" + fileLocation + ")";
//		} else {
//		  return fileLocation;
//		}
//	  };

//	  sourceMaps = {};

//	  getSourceMap = function(filename) {
//		var answer, ref1;
//		if (sourceMaps[filename]) {
//		  return sourceMaps[filename];
//		}
//		if (ref1 = path != null ? path.extname(filename) : void 0, indexOf.call(exports.FILE_EXTENSIONS, ref1) < 0) {
//		  return;
//		}
//		answer = exports._compileFile(filename, true);
//		return sourceMaps[filename] = answer.sourceMap;
//	  };

//	  Error.prepareStackTrace = function(err, stack) {
//		var frame, frames, getSourceMapping;
//		getSourceMapping = function(filename, line, column) {
//		  var answer, sourceMap;
//		  sourceMap = getSourceMap(filename);
//		  if (sourceMap) {
//			answer = sourceMap.sourceLocation([line - 1, column - 1]);
//		  }
//		  if (answer) {
//			return [answer[0] + 1, answer[1] + 1];
//		  } else {
//			return null;
//		  }
//		};
//		frames = (function() {
//		  var j, len1, results;
//		  results = [];
//		  for (j = 0, len1 = stack.length; j < len1; j++) {
//			frame = stack[j];
//			if (frame.getFunction() === exports.run) {
//			  break;
//			}
//			results.push("  at " + (formatSourcePosition(frame, getSourceMapping)));
//		  }
//		  return results;
//		})();
//		return (err.toString()) + "\n" + (frames.join('\n')) + "\n";
//	  };
  
	  return exports;
	};
	//#endregion
	
	return require('/coffee-script');
 })();
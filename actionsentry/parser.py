"""
Simple YAML parser for GitHub Actions workflow files.

This parser handles the subset of YAML used in GitHub Actions workflows:
- Mappings (key: value)
- Sequences (items with - prefix)
- Strings, numbers, booleans, null
- Comments (# ...)
- Multiline strings (|, >, |+, |-, >+, >-)
- Quoted strings (single and double)
- Flow sequences ([a, b, c])
- Flow mappings ({key: value})
- Anchors (&anchor) and aliases (*anchor)
- Nested structures

It also tracks line numbers for each parsed element to enable precise
finding reporting.
"""

import re
from typing import Any, Dict, List, Optional, Tuple


class YAMLParseError(Exception):
    """Raised when YAML parsing fails."""
    def __init__(self, message: str, line: int = 0):
        self.line = line
        super().__init__(f"Line {line}: {message}" if line else message)


class LineTracker:
    """Tracks line numbers during YAML parsing."""

    def __init__(self):
        self.node_lines: Dict[int, int] = {}  # id(node) -> line_number

    def track(self, node: Any, line: int):
        """Track the line number for a parsed node."""
        if node is not None:
            self.node_lines[id(node)] = line

    def get_line(self, node: Any) -> int:
        """Get the line number for a node. Returns 0 if unknown."""
        return self.node_lines.get(id(node), 0)


class SimpleYAMLParser:
    """A simple YAML parser for GitHub Actions workflow files."""

    def __init__(self):
        self.tracker = LineTracker()
        self.anchors: Dict[str, Any] = {}

    def parse(self, content: str) -> Tuple[Any, LineTracker]:
        """Parse YAML content and return (parsed_data, line_tracker)."""
        self.anchors = {}
        self.tracker = LineTracker()
        lines = content.split("\n")
        data, _ = self._parse_lines(lines, 0, 0)
        return data, self.tracker

    def _parse_lines(
        self, lines: List[str], start: int, base_indent: int
    ) -> Tuple[Any, int]:
        """Parse lines starting at `start` with the given base indentation."""
        if start >= len(lines):
            return None, start

        # Skip empty and comment lines to find first content line
        first_content = start
        while first_content < len(lines):
            stripped = lines[first_content].strip()
            if stripped == "" or stripped.startswith("#"):
                first_content += 1
            else:
                break

        if first_content >= len(lines):
            return None, first_content

        first_line = lines[first_content]
        stripped = first_line.strip()

        # Determine indentation of first content line
        indent = len(first_line) - len(first_line.lstrip())

        if indent < base_indent:
            return None, first_content

        # Check if this is a sequence (starts with -)
        if stripped.startswith("- ") or stripped == "-":
            return self._parse_sequence(lines, first_content, indent)

        # Check if this is a mapping (contains : followed by space or end of line)
        if self._is_mapping_line(stripped):
            return self._parse_mapping(lines, first_content, indent)

        # Scalar value
        value, next_line = self._parse_scalar_value(lines, first_content)
        return value, next_line

    def _is_mapping_line(self, stripped: str) -> bool:
        """Check if a stripped line starts a mapping entry."""
        # Skip flow sequences and flow mappings
        if stripped.startswith("[") or stripped.startswith("{"):
            return False
        # Look for "key: " or "key:" pattern
        # Must not be inside a string
        in_quote = False
        quote_char = None
        for i, ch in enumerate(stripped):
            if in_quote:
                if ch == quote_char:
                    in_quote = False
                continue
            if ch in ('"', "'"):
                in_quote = True
                quote_char = ch
                continue
            if ch == ":" and (i + 1 >= len(stripped) or stripped[i + 1] in (" ", "\t", "\n")):
                return True
        return False

    def _parse_mapping(
        self, lines: List[str], start: int, base_indent: int
    ) -> Tuple[Dict[str, Any], int]:
        """Parse a YAML mapping block."""
        result: Dict[str, Any] = {}
        self.tracker.track(result, start + 1)  # 1-indexed

        i = start
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Skip empty and comment lines
            if stripped == "" or stripped.startswith("#"):
                i += 1
                continue

            # Check indentation
            indent = len(line) - len(line.lstrip())
            if indent < base_indent:
                break
            if indent > base_indent:
                # This shouldn't happen in well-formed YAML at this level
                i += 1
                continue

            # Check for anchor
            if "&" in stripped:
                anchor_match = re.match(r"&(\S+)\s+", stripped)
                if anchor_match:
                    anchor_name = anchor_match.group(1)
                    stripped = stripped[anchor_match.end():]

            # Parse key
            key, colon_end = self._parse_key(stripped)
            if key is None:
                i += 1
                continue

            # Check for alias in value
            value_part = stripped[colon_end:].strip()

            # Handle alias reference
            alias_match = re.match(r"^\*(\S+)$", value_part)
            if alias_match:
                alias_name = alias_match.group(1)
                if alias_name in self.anchors:
                    result[key] = self.anchors[alias_name]
                else:
                    result[key] = None
                i += 1
                continue

            # Handle anchor on value
            anchor_name = None
            anchor_match = re.match(r"&(\S+)\s+", value_part)
            if anchor_match:
                anchor_name = anchor_match.group(1)
                value_part = value_part[anchor_match.end():]

            # Empty value - check next lines for nested content
            if value_part == "" or value_part.startswith("#"):
                # Look at next non-empty line
                next_i = i + 1
                while next_i < len(lines):
                    next_stripped = lines[next_i].strip()
                    if next_stripped == "" or next_stripped.startswith("#"):
                        next_i += 1
                        continue
                    next_indent = len(lines[next_i]) - len(lines[next_i].lstrip())
                    if next_indent > base_indent:
                        # Nested content
                        value, next_i = self._parse_lines(lines, next_i, next_indent)
                        result[key] = value
                        if anchor_name:
                            self.anchors[anchor_name] = value
                        i = next_i
                        break
                    else:
                        # No nested content, value is null
                        result[key] = None
                        if anchor_name:
                            self.anchors[anchor_name] = None
                        i = next_i
                        break
                else:
                    result[key] = None
                    i = next_i
                continue

            # Remove inline comments (but not inside strings)
            value_part = self._strip_inline_comment(value_part)

            # Flow sequence [...]
            if value_part.startswith("["):
                value = self._parse_flow_sequence(value_part)
                result[key] = value
                if anchor_name:
                    self.anchors[anchor_name] = value
                i += 1
                continue

            # Flow mapping {...}
            if value_part.startswith("{"):
                value = self._parse_flow_mapping(value_part)
                result[key] = value
                if anchor_name:
                    self.anchors[anchor_name] = value
                i += 1
                continue

            # Multiline string indicators
            if value_part.startswith("|") or value_part.startswith(">"):
                value, next_i = self._parse_multiline(lines, i + 1, value_part)
                result[key] = value
                if anchor_name:
                    self.anchors[anchor_name] = value
                i = next_i
                continue

            # Scalar value
            value = self._parse_scalar(value_part)
            result[key] = value
            if anchor_name:
                self.anchors[anchor_name] = value
            i += 1

        return result, i

    def _parse_sequence(
        self, lines: List[str], start: int, base_indent: int
    ) -> Tuple[List[Any], int]:
        """Parse a YAML sequence block."""
        result: List[Any] = []
        self.tracker.track(result, start + 1)  # 1-indexed

        i = start
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Skip empty and comment lines
            if stripped == "" or stripped.startswith("#"):
                i += 1
                continue

            indent = len(line) - len(line.lstrip())
            if indent < base_indent:
                break
            if indent > base_indent:
                i += 1
                continue

            # Must start with -
            if not stripped.startswith("- ") and stripped != "-":
                break

            # Get the value after "- "
            after_dash = stripped[1:].strip()

            if after_dash == "" or after_dash.startswith("#"):
                # Check next line for nested content
                next_i = i + 1
                while next_i < len(lines):
                    next_stripped = lines[next_i].strip()
                    if next_stripped == "" or next_stripped.startswith("#"):
                        next_i += 1
                        continue
                    next_indent = len(lines[next_i]) - len(lines[next_i].lstrip())
                    if next_indent > base_indent:
                        value, next_i = self._parse_lines(lines, next_i, next_indent)
                        result.append(value)
                        i = next_i
                        break
                    else:
                        result.append(None)
                        i = next_i
                        break
                else:
                    result.append(None)
                    i = next_i
                continue

            # Handle alias
            alias_match = re.match(r"^\*(\S+)$", after_dash)
            if alias_match:
                alias_name = alias_match.group(1)
                if alias_name in self.anchors:
                    result.append(self.anchors[alias_name])
                else:
                    result.append(None)
                i += 1
                continue

            # Handle anchor
            anchor_name = None
            anchor_match = re.match(r"&(\S+)\s+", after_dash)
            if anchor_match:
                anchor_name = anchor_match.group(1)
                after_dash = after_dash[anchor_match.end():]

            after_dash = self._strip_inline_comment(after_dash)

            # Nested mapping after "- key: value"
            if self._is_mapping_line(after_dash):
                # The mapping content after "- " starts at base_indent + 2
                # Collect all lines that belong to this sequence item
                item_indent = base_indent + 2  # indent of the mapping keys
                value, next_i = self._parse_sequence_item_mapping(
                    lines, i, after_dash, item_indent
                )
                result.append(value)
                if anchor_name:
                    self.anchors[anchor_name] = value
                i = next_i
                continue

            # Flow sequence
            if after_dash.startswith("["):
                value = self._parse_flow_sequence(after_dash)
                result.append(value)
                if anchor_name:
                    self.anchors[anchor_name] = value
                i += 1
                continue

            # Flow mapping
            if after_dash.startswith("{"):
                value = self._parse_flow_mapping(after_dash)
                result.append(value)
                if anchor_name:
                    self.anchors[anchor_name] = value
                i += 1
                continue

            # Scalar value
            value = self._parse_scalar(after_dash)
            result.append(value)
            if anchor_name:
                self.anchors[anchor_name] = value
            i += 1

        return result, i

    def _parse_sequence_item_mapping(
        self, lines: List[str], seq_line: int, first_key_value: str,
        item_indent: int
    ) -> Tuple[Dict[str, Any], int]:
        """Parse a mapping that is a sequence item (after '- key: value').

        The first key-value pair is given as first_key_value.
        Subsequent keys at item_indent or deeper are collected.
        """
        result: Dict[str, Any] = {}

        # Parse the first key-value pair
        key, colon_end = self._parse_key(first_key_value)
        if key is not None:
            value_part = first_key_value[colon_end:].strip()
            value_part = self._strip_inline_comment(value_part)
            if value_part:
                result[key] = self._parse_scalar(value_part)
            else:
                result[key] = None

        # Now parse subsequent lines that belong to this mapping
        i = seq_line + 1
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Skip empty and comment lines
            if stripped == "" or stripped.startswith("#"):
                i += 1
                continue

            indent = len(line) - len(line.lstrip())

            # Lines at item_indent are sibling keys of this mapping
            if indent == item_indent:
                # Parse this key-value pair
                key, colon_end = self._parse_key(stripped)
                if key is None:
                    i += 1
                    continue

                value_part = stripped[colon_end:].strip()

                # Handle alias
                alias_match = re.match(r"^\*(\S+)$", value_part)
                if alias_match:
                    alias_name = alias_match.group(1)
                    result[key] = self.anchors.get(alias_name)
                    i += 1
                    continue

                value_part = self._strip_inline_comment(value_part)

                # Empty value - check for nested content
                if value_part == "":
                    next_i = i + 1
                    while next_i < len(lines):
                        ns = lines[next_i].strip()
                        if ns == "" or ns.startswith("#"):
                            next_i += 1
                            continue
                        ni = len(lines[next_i]) - len(lines[next_i].lstrip())
                        if ni > item_indent:
                            value, next_i = self._parse_lines(
                                lines, next_i, ni
                            )
                            result[key] = value
                            i = next_i
                            break
                        else:
                            result[key] = None
                            i = next_i
                            break
                    else:
                        result[key] = None
                        i = next_i
                    continue

                # Flow sequence
                if value_part.startswith("["):
                    result[key] = self._parse_flow_sequence(value_part)
                    i += 1
                    continue

                # Flow mapping
                if value_part.startswith("{"):
                    result[key] = self._parse_flow_mapping(value_part)
                    i += 1
                    continue

                # Multiline string
                if value_part.startswith("|") or value_part.startswith(">"):
                    value, next_i = self._parse_multiline(
                        lines, i + 1, value_part
                    )
                    result[key] = value
                    i = next_i
                    continue

                # Scalar value
                result[key] = self._parse_scalar(value_part)
                i += 1
                continue

            # Lines indented deeper than item_indent are nested content
            # of the last key - but we already handle that above
            if indent > item_indent:
                # This might be nested content of a key we already parsed
                # with an empty value. Skip for now.
                i += 1
                continue

            # Line at a lower indent - we're done with this mapping
            break

        return result, i

    def _parse_key(self, stripped: str) -> Tuple[Optional[str], int]:
        """Parse a mapping key and return (key, index_after_colon)."""
        in_quote = False
        quote_char = None
        for i, ch in enumerate(stripped):
            if in_quote:
                if ch == quote_char:
                    in_quote = False
                continue
            if ch in ('"', "'"):
                in_quote = True
                quote_char = ch
                continue
            if ch == ":" and (i + 1 >= len(stripped) or stripped[i + 1] in (" ", "\t")):
                key_str = stripped[:i].strip()
                # Unquote if needed
                key_str = self._unquote(key_str)
                return key_str, i + 1
        return None, 0

    def _parse_scalar(self, value: str) -> Any:
        """Parse a scalar YAML value."""
        if not value:
            return ""

        # Quoted string
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return self._unquote(value)

        # Boolean
        if value.lower() in ("true", "yes", "on"):
            return True
        if value.lower() in ("false", "no", "off"):
            return False

        # Null
        if value.lower() in ("null", "~", ""):
            return None

        # Integer
        try:
            return int(value)
        except ValueError:
            pass

        # Float
        try:
            return float(value)
        except ValueError:
            pass

        # Plain string
        return value

    def _parse_scalar_value(
        self, lines: List[str], start: int
    ) -> Tuple[Any, int]:
        """Parse a scalar value at the given line position."""
        if start >= len(lines):
            return None, start
        stripped = lines[start].strip()
        stripped = self._strip_inline_comment(stripped)
        return self._parse_scalar(stripped), start + 1

    def _parse_flow_sequence(self, text: str) -> List[Any]:
        """Parse a flow sequence like [a, b, c]."""
        text = text.strip()
        if not text.startswith("[") or not text.endswith("]"):
            return []
        inner = text[1:-1].strip()
        if not inner:
            return []
        items = []
        # Simple split by comma (doesn't handle nested structures)
        for item in inner.split(","):
            item = item.strip()
            if item:
                items.append(self._parse_scalar(item))
        return items

    def _parse_flow_mapping(self, text: str) -> Dict[str, Any]:
        """Parse a flow mapping like {key: value, key2: value2}."""
        text = text.strip()
        if not text.startswith("{") or not text.endswith("}"):
            return {}
        inner = text[1:-1].strip()
        if not inner:
            return {}
        result = {}
        for pair in inner.split(","):
            pair = pair.strip()
            if ":" in pair:
                key, _, val = pair.partition(":")
                result[key.strip()] = self._parse_scalar(val.strip())
        return result

    def _parse_multiline(
        self, lines: List[str], start: int, indicator: str
    ) -> Tuple[str, int]:
        """Parse a multiline string block (| or >)."""
        # Parse indicator: |, |+, |-, >, >+, >-
        mode = indicator[0]  # | or >
        strip_mode = "clip"  # default
        if len(indicator) > 1:
            if "+" in indicator:
                strip_mode = "keep"
            elif "-" in indicator:
                strip_mode = "strip"

        # Determine indent of block
        if start >= len(lines):
            return "", start

        # Find the indent of the first content line
        block_indent = None
        i = start
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if stripped == "" or stripped.startswith("#"):
                i += 1
                continue
            block_indent = len(line) - len(line.lstrip())
            break

        if block_indent is None:
            return "", i

        content_lines = []
        i = start
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if stripped == "":
                content_lines.append("")
                i += 1
                continue

            current_indent = len(line) - len(line.lstrip())
            if current_indent < block_indent:
                break

            content_lines.append(stripped)
            i += 1

        # Join lines
        if mode == ">":
            # Fold mode: replace single newlines with spaces
            text = ""
            prev_empty = False
            for j, cl in enumerate(content_lines):
                if cl == "":
                    prev_empty = True
                    continue
                if prev_empty:
                    text += "\n"
                    prev_empty = False
                elif text:
                    text += " "
                text += cl
        else:
            # Literal mode: preserve newlines
            text = "\n".join(content_lines)

        # Apply strip mode
        if strip_mode == "strip":
            text = text.strip("\n")
        elif strip_mode == "clip":
            text = text.rstrip("\n")
        # "keep" preserves all trailing newlines

        return text, i

    def _strip_inline_comment(self, value: str) -> str:
        """Remove inline comments from a value, respecting quotes."""
        in_quote = False
        quote_char = None
        i = 0
        while i < len(value):
            ch = value[i]
            if in_quote:
                if ch == quote_char:
                    in_quote = False
                i += 1
                continue
            if ch in ('"', "'"):
                in_quote = True
                quote_char = ch
                i += 1
                continue
            if ch == "#":
                return value[:i].rstrip()
            i += 1
        return value

    def _unquote(self, value: str) -> str:
        """Remove surrounding quotes from a string."""
        if len(value) >= 2:
            if (value[0] == '"' and value[-1] == '"') or \
               (value[0] == "'" and value[-1] == "'"):
                return value[1:-1]
        return value


def parse_yaml(content: str) -> Tuple[Any, LineTracker]:
    """Parse YAML content and return (data, line_tracker).

    This is the main entry point for the YAML parser.
    """
    parser = SimpleYAMLParser()
    return parser.parse(content)


def parse_yaml_file(file_path: str) -> Tuple[Optional[Any], Optional[LineTracker], Optional[str]]:
    """Parse a YAML file and return (data, line_tracker, error)."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except IOError as e:
        return None, None, str(e)

    try:
        data, tracker = parse_yaml(content)
        return data, tracker, None
    except Exception as e:
        return None, None, str(e)

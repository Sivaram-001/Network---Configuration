import difflib
from typing import Dict, Any, List

def generate_config_diff(old_content: str, new_content: str) -> Dict[str, Any]:
    """
    Generates a line-by-line diff between old_content and new_content.
    Categorizes lines into: added, removed, modified, unchanged.
    Returns:
        raw_diff: str (unified diff format)
        added_count: int
        removed_count: int
        modified_count: int
        diff_json: Dict containing line list and statistics
    """
    old_lines = old_content.splitlines()
    new_lines = new_content.splitlines()

    # 1. Generate Raw Unified Diff
    raw_diff_list = list(difflib.unified_diff(
        old_lines, new_lines,
        fromfile='old_config', tofile='new_config',
        lineterm=''
    ))
    raw_diff = "\n".join(raw_diff_list)

    # 2. Detailed line-by-line classification
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    diff_lines = []
    
    added_count = 0
    removed_count = 0
    modified_count = 0
    unchanged_count = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            for idx in range(i2 - i1):
                diff_lines.append({
                    "type": "unchanged",
                    "content": old_lines[i1 + idx],
                    "old_lineno": i1 + idx + 1,
                    "new_lineno": j1 + idx + 1
                })
                unchanged_count += 1
        
        elif tag == 'delete':
            for idx in range(i2 - i1):
                diff_lines.append({
                    "type": "removed",
                    "content": old_lines[i1 + idx],
                    "old_lineno": i1 + idx + 1,
                    "new_lineno": None
                })
                removed_count += 1
                
        elif tag == 'insert':
            for idx in range(j2 - j1):
                diff_lines.append({
                    "type": "added",
                    "content": new_lines[j1 + idx],
                    "old_lineno": None,
                    "new_lineno": j1 + idx + 1
                })
                added_count += 1
                
        elif tag == 'replace':
            old_sub = old_lines[i1:i2]
            new_sub = new_lines[j1:j2]
            min_len = min(len(old_sub), len(new_sub))
            
            # Match line by line as modified for the overlapping portion
            for idx in range(min_len):
                diff_lines.append({
                    "type": "modified",
                    "content": new_sub[idx],
                    "old_content": old_sub[idx],
                    "new_content": new_sub[idx],
                    "old_lineno": i1 + idx + 1,
                    "new_lineno": j1 + idx + 1
                })
                modified_count += 1
            
            # The remaining lines in old block are deletions (removed)
            if len(old_sub) > min_len:
                for idx in range(min_len, len(old_sub)):
                    diff_lines.append({
                        "type": "removed",
                        "content": old_sub[idx],
                        "old_lineno": i1 + idx + 1,
                        "new_lineno": None
                    })
                    removed_count += 1
            
            # The remaining lines in new block are insertions (added)
            elif len(new_sub) > min_len:
                for idx in range(min_len, len(new_sub)):
                    diff_lines.append({
                        "type": "added",
                        "content": new_sub[idx],
                        "old_lineno": None,
                        "new_lineno": j1 + idx + 1
                    })
                    added_count += 1

    return {
        "raw_diff": raw_diff,
        "added_count": added_count,
        "removed_count": removed_count,
        "modified_count": modified_count,
        "diff_json": {
            "statistics": {
                "added": added_count,
                "removed": removed_count,
                "modified": modified_count,
                "unchanged": unchanged_count,
                "total_old": len(old_lines),
                "total_new": len(new_lines)
            },
            "lines": diff_lines
        }
    }

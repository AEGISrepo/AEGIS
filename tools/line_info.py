import re
from functools import cache


class LineInfo:
    def __init__(self, patch_text: str):
        self.patch = patch_text
        self.file_name = None
        self.function_name = None
        self.hunks = []
        self.modifications = []
        self.total_additions = 0
        self.total_deletions = 0
        self.total_context_lines = 0

    @cache
    def extract_file_and_function(self):
        file_header = re.search(r'diff --git a/(.*?) b/', self.patch)
        if not file_header:
            raise ValueError("Patch header for file not found")
        self.file_name = file_header.group(1)
        func_header = re.search(r'@@.* (\w+)\s*\(', self.patch)
        if not func_header:
            raise ValueError("Function name not found in patch header")
        self.function_name = func_header.group(1)
        return self.file_name, self.function_name

    def parse_hunks(self):
        hunk_pattern = re.compile(
            r'^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@', re.MULTILINE)
        matches = list(hunk_pattern.finditer(self.patch))
        if not matches:
            raise ValueError("No hunk headers detected")
        for i, m in enumerate(matches):
            old_start = int(m.group(1)) - 1
            old_count = int(m.group(2)) if m.group(2) else 1
            new_start = int(m.group(3)) - 1
            new_count = int(m.group(4)) if m.group(4) else 1
            hunk_end = len(self.patch) if (
                i + 1) >= len(matches) else matches[i + 1].start()
            hunk_body = self.patch[m.end():hunk_end]
            processed_lines = self._process_hunk_lines(
                hunk_body, old_start, new_start)
            self.hunks.append({
                'header': {
                    'old_start': old_start,
                    'old_count': old_count,
                    'new_start': new_start,
                    'new_count': new_count
                },
                'lines': processed_lines
            })

    def _process_hunk_lines(self, text: str, o_start: int, n_start: int):
        lines_raw = text.splitlines()
        processed = []
        current_old = o_start
        current_new = n_start
        for line in lines_raw:
            if line.startswith(' '):
                processed.append(
                    {'type': 'context', 'content': line[1:], 'old_line': current_old, 'new_line': current_new})
                current_old += 1
                current_new += 1
                self.total_context_lines += 1
            elif line.startswith('-'):
                processed.append(
                    {'type': 'deletion', 'content': line[1:], 'old_line': current_old, 'new_line': None})
                current_old += 1
                self.total_deletions += 1
            elif line.startswith('+'):
                processed.append(
                    {'type': 'addition', 'content': line[1:], 'old_line': None, 'new_line': current_new})
                current_new += 1
                self.total_additions += 1
            else:
                processed.append({'type': 'context', 'content': line,
                                 'old_line': current_old, 'new_line': current_new})
                current_old += 1
                current_new += 1
                self.total_context_lines += 1
        return processed

    def group_addition_lines(self):
        for hunk in self.hunks:
            lines = hunk['lines']
            idx = 0
            while idx < len(lines):
                if lines[idx]['type'] == 'addition':
                    start = idx
                    while (idx + 1) < len(lines) and lines[idx + 1]['type'] == 'addition':
                        idx += 1
                    end = idx
                    added_lines = [(lines[i]['new_line'], lines[i]['content'])
                                   for i in range(start, end + 1)]
                    prev_context = None
                    for j in range(start - 1, -1, -1):
                        if lines[j]['type'] in ('context', 'deletion'):
                            prev_context = (
                                lines[j]['old_line'], lines[j]['content'])
                            break
                    next_context = None
                    for j in range(end + 1, len(lines)):
                        if lines[j]['type'] in ('context', 'deletion'):
                            next_context = (
                                lines[j]['old_line'], lines[j]['content'])
                            break
                    self.modifications.append({
                        'hunk_header': hunk['header'],
                        'added_block': added_lines,
                        'prev_context': prev_context,
                        'next_context': next_context
                    })
                    idx = end + 1
                else:
                    idx += 1

    def compute_statistics(self):
        return {
            'total_hunks': len(self.hunks),
            'total_additions': self.total_additions,
            'total_deletions': self.total_deletions,
            'total_context_lines': self.total_context_lines
        }

    def analyze(self):
        self.extract_file_and_function()
        self.parse_hunks()
        self.group_addition_lines()
        stats = self.compute_statistics()
        return {
            'file': self.file_name,
            'function': self.function_name,
            'statistics': stats,
            'modifications': self.modifications
        }


def main():
    sample_patch = """
While looking at a related syzbot report involving neigh_periodic_work(),
I found that I forgot to add an annotation when deleting an
RCU protected item from a list.

Readers use rcu_deference(*np), we need to use either
rcu_assign_pointer() or WRITE_ONCE() on writer side
to prevent store tearing.

I use rcu_assign_pointer() to have lockdep support,
this was the choice made in neigh_flush_dev().

Fixes: 767e97e1e0db ("neigh: RCU conversion of struct neighbour")
Signed-off-by: Eric Dumazet <edumazet@google.com>
Reviewed-by: David Ahern <dsahern@kernel.org>
Reviewed-by: Simon Horman <horms@kernel.org>
Signed-off-by: David S. Miller <davem@davemloft.net>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 net/core/neighbour.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/net/core/neighbour.c b/net/core/neighbour.c
index af022db48b7a99..a385086091fd3e 100644
--- a/net/core/neighbour.c
+++ b/net/core/neighbour.c
@@ -930,7 +930,9 @@ static void neigh_periodic_work(struct work_struct *work)
                (state == NUD_FAILED ||
                !time_in_range_open(jiffies, n->used,
                                   n->used + NEIGH_VAR(n->parms, GC_STALETIME)))) {
-                *np = n->next;
+                rcu_assign_pointer(*np,
+                    rcu_dereference_protected(n->next,
+                        lockdep_is_held(&tbl->lock)));
                   neigh_mark_dead(n);
                  write_unlock(&n->lock);
                  neigh_cleanup_and_release(n);
@@ -940,6 +942,7 @@ static void neigh_periodic_work(struct work_struct *work)
                (state == NUD_FAILED ||
                !time_in_range_open(jiffies, n->used,
                                   n->used + NEIGH_VAR(n->parms, GC_STALETIME)))) {
+                /* Additional comment */
                   neigh_mark_dead(n);
                  write_unlock(&n->lock);
                  neigh_cleanup_and_release(n);
-- 
cgit 1.2.3-korg
"""
    try:
        analyzer = LineInfo(sample_patch)
        analysis_result = analyzer.analyze()
        print("File name:", analysis_result['file'])
        print("Function name:", analysis_result['function'])
        stats = analysis_result['statistics']
        print("Total hunks:", stats['total_hunks'])
        print("Total additions:", stats['total_additions'])
        print("Total deletions:", stats['total_deletions'])
        print("Total context lines:", stats['total_context_lines'])
        for idx, mod in enumerate(analysis_result['modifications'], start=1):
            print(f"\nModification {idx}:")
            print("Added block:")
            for line_num, content in mod['added_block']:
                print(f"  New file line {line_num}: {content}")
            if mod['prev_context']:
                print(
                    f"Previous context line ({mod['prev_context'][0]}): {mod['prev_context'][1]}")
            else:
                print("Previous context line: None")
            if mod['next_context']:
                print(
                    f"Next context line ({mod['next_context'][0]}): {mod['next_context'][1]}")
            else:
                print("Next context line: None")
    except Exception as error:
        print("Error encountered:", error)


if __name__ == "__main__":
    main()

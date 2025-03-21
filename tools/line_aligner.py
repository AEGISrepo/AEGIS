from loguru import logger
from tree_sitter import Language, Parser, Node
from tree_sitter_c import language as c_language


C_LANGUAGE = Language(c_language())
parser = Parser(C_LANGUAGE)


SAMPLE_C_CODE = """
static void neigh_invalidate(struct neighbour *neigh)
	__releases(neigh->lock)
	__acquires(neigh->lock)
{
	struct sk_buff *skb;

	NEIGH_CACHE_STAT_INC(neigh->tbl, res_failed);
	neigh_dbg(2, "neigh %p is failed\n", neigh);
	neigh->updated = jiffies;

	/* It is very thin place. report_unreachable is very complicated
	   routine. Particularly, it can hit the same neighbour entry!

	   So that, we try to be accurate and avoid dead loop. --ANK
	 */
	while (neigh->nud_state == NUD_FAILED &&
	       (skb = __skb_dequeue(&neigh->arp_queue)) != NULL) {
		write_unlock(&neigh->lock);
		neigh->ops->error_report(neigh, skb);
		write_lock(&neigh->lock);
	}
	__skb_queue_purge(&neigh->arp_queue);
	neigh->arp_queue_len_bytes = 0;
}
"""

TARGET_SOURCE_LINE = " write_unlock(&neigh->lock) "


class ASTNodeComparator:
    def __init__(self):
        pass

    def compare(self, node_a: Node, node_b: Node) -> bool:
        if node_a.type != node_b.type and node_b.type != "ERROR":
            return False
        if node_a.type == "identifier":
            return node_a.text == node_b.text
        if node_a.type == "field_expression":
            field_a = node_a.child_by_field_name("field")
            field_b = node_b.child_by_field_name("field")
            if field_a is None or field_b is None or field_a.text != field_b.text:
                return False
        if node_a.type in ["number_literal", "string_literal", "char_literal"]:
            return node_a.text == node_b.text
        if len(node_a.children) != len(node_b.children):
            return False
        for child_a, child_b in zip(node_a.children, node_b.children):
            if not self.compare(child_a, child_b):
                return False
        return True


class ASTMatcher:
    def __init__(self):
        self.comparator = ASTNodeComparator()

    def search(self, root: Node, target: Node) -> list:
        found_lines = []
        if self.comparator.compare(root, target):
            found_lines.append(root.start_point[0] + 1)
        for child in root.children:
            found_lines.extend(self.search(child, target))
        return found_lines


class Aligner:
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.parser = parser
        self.lang = C_LANGUAGE
        self.matcher = ASTMatcher()

    def parse_code(self, code: str) -> Node:
        tree = self.parser.parse(bytes(code, "utf8"))
        return tree.root_node

    def refine_target_node(self, node: Node) -> Node:
        refined = node
        if len(refined.children) == 1:
            refined = refined.children[0]
        if refined.type == "ERROR" and len(refined.children) == 1:
            refined = refined.children[0]
        return refined

    def locate_target_line(self, target_source: str) -> int:
        main_root = self.parse_code(self.source_code)
        target_root = self.parse_code(target_source)
        if len(target_root.children) == 1:
            target_root = target_root.children[0]
        target_root = self.refine_target_node(target_root)
        matching_lines = self.matcher.search(main_root, target_root)
        if not matching_lines:
            logger.info("No matching target node found in the source code.")
            return None
        if len(matching_lines) > 1:
            logger.info(
                "Multiple matches found; selecting the first occurrence.")
        return matching_lines[0]


def main():
    locator = Aligner(SAMPLE_C_CODE)
    line_no = locator.locate_target_line(TARGET_SOURCE_LINE)
    if line_no is None:
        print("Target node not found.")
    else:
        print(
            f"Target line '{TARGET_SOURCE_LINE.strip()}' is located at line {line_no}.")


if __name__ == "__main__":
    main()

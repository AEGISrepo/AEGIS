import argparse
import logging
from functools import cache
from tree_sitter import Language, Parser, Node
from tree_sitter_c import language as c_language

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

C_LANGUAGE = Language(c_language())
parser = Parser()
parser.set_language(C_LANGUAGE)


class Extractor:
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.tree = self._parse_source()

    def _parse_source(self):
        try:
            return parser.parse(bytes(self.source_code, "utf8")).root_node
        except Exception as error:
            logging.error("Error parsing source: %s", error)
            raise

    @cache
    def _extract_identifier(self, declarator: Node) -> str:
        identifier = None
        for field in ["declarator", "name", "direct_declarator"]:
            candidate = declarator.child_by_field_name(field)
            if candidate:
                try:
                    identifier = candidate.text.decode("utf8")
                    if identifier:
                        break
                except Exception as error:
                    logging.error(
                        "Failed to decode candidate for field %s: %s", field, error)
        return identifier

    @cache
    def _extract_parameters(self, declarator: Node) -> str:
        parameters_node = declarator.child_by_field_name("parameters")
        if parameters_node:
            try:
                return parameters_node.text.decode("utf8")
            except Exception as error:
                logging.error("Failed to decode parameters: %s", error)
        return ""

    def _traverse_for_function(self, node: Node, target_function: str):
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if declarator:
                func_identifier = self._extract_identifier(declarator)
                if func_identifier == target_function:
                    try:
                        function_text = node.text.decode("utf8")
                    except Exception as error:
                        logging.error(
                            "Failed to decode function definition: %s", error)
                        function_text = ""
                    start_line = node.start_point[0] + 1
                    parameters = self._extract_parameters(declarator)
                    return {
                        "name": func_identifier,
                        "definition": function_text,
                        "start_line": start_line,
                        "parameters": parameters
                    }
        for child in node.children:
            result = self._traverse_for_function(child, target_function)
            if result:
                return result
        return None

    def extract_function_definition(self, function_name: str) -> dict:
        result = self._traverse_for_function(self.tree, function_name)
        if result:
            return result
        raise ValueError(
            f"Function '{function_name}' not found in the source code.")


def load_source_from_file(file_path: str) -> str:
    try:
        with open(file_path, "r", encoding="utf8") as file:
            return file.read()
    except Exception as error:
        logging.error("Failed to read file %s: %s", file_path, error)
        raise


def main():
    arg_parser = argparse.ArgumentParser(
        description="Extract a specified function definition from a C source file using tree-sitter."
    )
    arg_parser.add_argument("file", help="Path to the C source file.")
    arg_parser.add_argument(
        "function", help="Name of the function to extract.")
    args = arg_parser.parse_args()

    source_code = load_source_from_file(args.file)
    extractor = Extractor(source_code)
    try:
        func_info = extractor.extract_function_definition(args.function)
        print("Extracted Function Information:")
        print("Function Name:", func_info.get("name"))
        print("Starting Line:", func_info.get("start_line"))
        print("Parameters:", func_info.get("parameters"))
        print("Definition:\n", func_info.get("definition"))
    except ValueError as error:
        logging.error(error)
        print(error)


if __name__ == "__main__":
    main()

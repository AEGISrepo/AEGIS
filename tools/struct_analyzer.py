import argparse
import concurrent.futures
from functools import cache
from io import StringIO
from loguru import logger
from tree_sitter import Language, Parser, Node
from tree_sitter_c import language as c_language

C_LANGUAGE = Language(c_language())
parser = Parser()
parser.set_language(C_LANGUAGE)


class CCodeAnalyzer:
    """
    CCodeAnalyzer performs advanced static analysis on C source code.

    It extracts:
      - Function definitions along with their names, parameters, and source code lines.
      - Function call expressions (while filtering out standard library calls) and builds a call graph.
      - Loop constructs (for, while, do-while) with condition and update expressions.
      - Conditional constructs (if and switch statements) including nested branches.
      - Variable declarations found within the code.

    Additionally, it computes and reports various code metrics.
    """

    def __init__(self, source_code: str):
        """
        Initialize the analyzer with the provided source code.
        """
        self.source_code = source_code
        self.tree = self.parse_code(source_code)
        self.metrics = {
            "functions": 0,
            "function_calls": 0,
            "loops": 0,
            "conditionals": 0,
            "variable_declarations": 0
        }
        # Dictionary mapping each function to the set of function names it calls.
        self.call_graph = {}

    def parse_code(self, source_code: str):
        """
        Parse the provided C source code and return the syntax tree.
        """
        try:
            tree = parser.parse(bytes(source_code, "utf-8"))
            logger.debug("Successfully parsed the source code.")
            return tree
        except Exception as e:
            logger.error(f"Error parsing source code: {e}")
            raise

    @cache
    def extract_function_info(self, node: Node):
        """
        Extract function definition information from a function definition node.

        Returns a string describing the function name, its parameters, and its location.
        """
        declarator = node.child_by_field_name('declarator')
        if not declarator:
            return None

        # Attempt to extract the function name using various possible fields.
        function_name_node = (
            declarator.child_by_field_name('declarator') or
            declarator.child_by_field_name('name') or
            declarator.child_by_field_name('direct_declarator')
        )
        if not function_name_node:
            return None

        try:
            function_name = function_name_node.text.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decoding function name: {e}")
            function_name = "<unknown>"

        # Extract parameters if available.
        parameters_node = declarator.child_by_field_name('parameters')
        parameters = ""
        if parameters_node:
            try:
                parameters = parameters_node.text.decode('utf-8').strip('()')
            except Exception as e:
                logger.error(f"Error decoding parameters: {e}")
                parameters = ""

        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1

        # Update function count metric.
        self.metrics["functions"] += 1
        # Initialize call graph entry for this function.
        self.call_graph[function_name] = set()

        return f"Function Definition: {function_name}({parameters})\nLines: {start_line}-{end_line}\n"

    @cache
    def extract_function_calls(self, node: Node, indent_level=0, current_function="<global>"):
        """
        Recursively extract function call expressions from the syntax tree.

        Standard library calls such as printf, perror, etc. are filtered out.
        Also, records the call in the call graph when inside a function.
        """
        calls = []
        if node.type == 'call_expression':
            function_field = node.child_by_field_name('function')
            if function_field:
                try:
                    function_name = function_field.text.decode('utf-8')
                except Exception as e:
                    logger.error(f"Error decoding function call name: {e}")
                    function_name = "<unknown>"
                # Filter out standard library functions.
                if function_name not in ['printf', 'perror', 'fprintf', 'puts', 'fputs', 'dprintf', 'atoi']:
                    arguments_node = node.child_by_field_name('arguments')
                    if arguments_node:
                        try:
                            arguments = arguments_node.text.decode(
                                'utf-8').strip('()')
                        except Exception as e:
                            logger.error(
                                f"Error decoding function arguments: {e}")
                            arguments = ""
                    else:
                        arguments = ""
                    line_number = node.start_point[0] + 1
                    indent = "  " * indent_level
                    call_repr = f"{indent}Line {line_number}: {function_name}({arguments})"
                    calls.append(call_repr)
                    # Record the call in the call graph.
                    if current_function != "<global>":
                        self.call_graph[current_function].add(function_name)
                    self.metrics["function_calls"] += 1

        # Recursively process children nodes.
        for child in node.children:
            # Skip loop constructs to avoid duplicate extraction.
            if child.type not in ['for_statement', 'while_statement', 'do_statement']:
                calls.extend(self.extract_function_calls(
                    child, indent_level, current_function))
        return calls

    @cache
    def extract_loop_info(self, node: Node, indent_level=0, visited_nodes=None):
        """
        Recursively extract loop constructs (for, while, and do-while) from the syntax tree.

        Provides details about the loop condition and update expressions (if applicable).
        """
        if visited_nodes is None:
            visited_nodes = set()

        loops = []
        if node.id in visited_nodes:
            return loops

        if node.type in ['for_statement', 'while_statement', 'do_statement']:
            visited_nodes.add(node.id)
            loop_type = node.type
            condition_node = node.child_by_field_name('condition')
            condition = ""
            if condition_node:
                try:
                    condition = condition_node.text.decode('utf-8').strip('()')
                except Exception as e:
                    logger.error(f"Error decoding loop condition: {e}")
                    condition = ""

            update = ""
            if loop_type == 'for_statement':
                update_node = node.child_by_field_name('update')
                if update_node:
                    try:
                        update = update_node.text.decode('utf-8').strip()
                    except Exception as e:
                        logger.error(f"Error decoding for loop update: {e}")
                        update = ""

            line_number = node.start_point[0] + 1
            indent = "  " * indent_level
            if loop_type == 'for_statement':
                loop_repr = f"{indent}Line {line_number}: {loop_type} (condition: {condition}, update: {update})"
            else:
                loop_repr = f"{indent}Line {line_number}: {loop_type} (condition: {condition})"
            loops.append(loop_repr)
            self.metrics["loops"] += 1

            # Process the loop body for nested constructs.
            body_node = node.child_by_field_name('body')
            if body_node:
                loops.extend(self.extract_function_calls(
                    body_node, indent_level + 1))
                loops.extend(self.extract_loop_info(
                    body_node, indent_level + 1, visited_nodes))

        for child in node.children:
            loops.extend(self.extract_loop_info(
                child, indent_level, visited_nodes))
        return loops

    @cache
    def extract_conditional_info(self, node: Node, indent_level=0):
        """
        Recursively extract conditional constructs (if and switch statements) from the syntax tree.

        Captures conditions, then and else branches, and for switch statements, includes case labels.
        """
        conditionals = []
        indent = "  " * indent_level

        if node.type == 'if_statement':
            condition_node = node.child_by_field_name('condition')
            condition = ""
            if condition_node:
                try:
                    condition = condition_node.text.decode('utf-8').strip('()')
                except Exception as e:
                    logger.error(f"Error decoding if condition: {e}")
                    condition = ""
            line_number = node.start_point[0] + 1
            cond_repr = f"{indent}Line {line_number}: if (condition: {condition})"
            conditionals.append(cond_repr)
            self.metrics["conditionals"] += 1

            consequence = node.child_by_field_name('consequence')
            alternative = node.child_by_field_name('alternative')
            if consequence:
                conditionals.append(f"{indent}  then:")
                conditionals.extend(self.extract_conditional_info(
                    consequence, indent_level + 2))
            if alternative:
                conditionals.append(f"{indent}  else:")
                conditionals.extend(self.extract_conditional_info(
                    alternative, indent_level + 2))

        elif node.type == 'switch_statement':
            condition_node = node.child_by_field_name('condition')
            condition = ""
            if condition_node:
                try:
                    condition = condition_node.text.decode('utf-8').strip('()')
                except Exception as e:
                    logger.error(f"Error decoding switch condition: {e}")
                    condition = ""
            line_number = node.start_point[0] + 1
            cond_repr = f"{indent}Line {line_number}: switch (condition: {condition})"
            conditionals.append(cond_repr)
            self.metrics["conditionals"] += 1

            # Process case and default labels.
            for child in node.children:
                if child.type in ['case_statement', 'default_statement']:
                    try:
                        label_text = child.text.decode('utf-8').strip()
                    except Exception as e:
                        logger.error(f"Error decoding switch case label: {e}")
                        label_text = "<unknown>"
                    conditionals.append(f"{indent}  {label_text}")

        # Recursively process all child nodes.
        for child in node.children:
            conditionals.extend(
                self.extract_conditional_info(child, indent_level))
        return conditionals

    @cache
    def extract_variable_declarations(self, node: Node, indent_level=0):
        """
        Recursively extract variable declaration statements from the syntax tree.

        For each declaration node, the full text is captured along with its source code line.
        """
        variables = []
        indent = "  " * indent_level

        if node.type == 'declaration':
            try:
                decl_text = node.text.decode('utf-8').strip()
            except Exception as e:
                logger.error(f"Error decoding variable declaration: {e}")
                decl_text = "<unknown declaration>"
            line_number = node.start_point[0] + 1
            var_repr = f"{indent}Line {line_number}: {decl_text}"
            variables.append(var_repr)
            self.metrics["variable_declarations"] += 1

        for child in node.children:
            variables.extend(
                self.extract_variable_declarations(child, indent_level))
        return variables

    def traverse_tree(self, node: Node, output_stream: StringIO, current_function="<global>"):
        """
        Recursively traverse the syntax tree to extract and record various constructs.

        The analysis includes function definitions, function calls, loops, conditionals, and variable declarations.
        """
        if node.type == 'function_definition':
            function_info = self.extract_function_info(node)
            if function_info:
                output_stream.write(function_info)
            # Identify current function name for call graph recording.
            declarator = node.child_by_field_name('declarator')
            function_name_node = None
            if declarator:
                function_name_node = (
                    declarator.child_by_field_name('declarator') or
                    declarator.child_by_field_name('name') or
                    declarator.child_by_field_name('direct_declarator')
                )
            if function_name_node:
                try:
                    current_function = function_name_node.text.decode('utf-8')
                except Exception as e:
                    logger.error(f"Error decoding current function name: {e}")
                    current_function = "<unknown>"
            body_node = node.child_by_field_name('body')
            if body_node:
                # Extract function calls.
                output_stream.write("Function Calls within Function Body:\n")
                calls = self.extract_function_calls(
                    body_node, indent_level=1, current_function=current_function)
                for call in calls:
                    output_stream.write(call + "\n")
                output_stream.write("\n")
                # Extract loop constructs.
                output_stream.write("Loop Constructs within Function Body:\n")
                loops = self.extract_loop_info(body_node, indent_level=1)
                for loop in loops:
                    output_stream.write(loop + "\n")
                output_stream.write("\n")
                # Extract conditional constructs.
                output_stream.write(
                    "Conditional Constructs within Function Body:\n")
                conditionals = self.extract_conditional_info(
                    body_node, indent_level=1)
                for cond in conditionals:
                    output_stream.write(cond + "\n")
                output_stream.write("\n")
                # Extract variable declarations.
                output_stream.write(
                    "Variable Declarations within Function Body:\n")
                variables = self.extract_variable_declarations(
                    body_node, indent_level=1)
                for var in variables:
                    output_stream.write(var + "\n")
                output_stream.write("\n")
        # Continue traversing all child nodes.
        for child in node.children:
            self.traverse_tree(child, output_stream, current_function)

    def build_call_graph(self):
        """
        Return the call graph as a dictionary mapping function names to the list of functions they call.
        """
        return {func: list(calls) for func, calls in self.call_graph.items()}

    def compute_metrics(self):
        """
        Return a dictionary of computed code metrics.
        """
        return self.metrics

    def analyze(self):
        """
        Perform the complete analysis of the C source code and return a comprehensive report.

        The report includes detailed extraction results, computed metrics, and the function call graph.
        """
        output = StringIO()
        self.traverse_tree(self.tree.root_node, output)
        analysis_report = output.getvalue()

        # Append metrics summary.
        metrics_summary = "\nAnalysis Metrics:\n"
        for key, value in self.metrics.items():
            metrics_summary += f"  {key}: {value}\n"
        output.write(metrics_summary)

        # Append call graph details.
        call_graph = self.build_call_graph()
        output.write("\nCall Graph:\n")
        for func, calls in call_graph.items():
            output.write(
                f"  {func} calls: {', '.join(calls) if calls else 'None'}\n")

        return output.getvalue()


def process_file(file_path: str):
    """
    Read a C source code file, analyze its content, and return the analysis report.
    """
    logger.info(f"Processing file: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            source_code = file.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return ""
    analyzer = CCodeAnalyzer(source_code)
    return analyzer.analyze()


def analyze_multiple_files(file_paths):
    """
    Analyze multiple C source files concurrently.

    Returns a dictionary mapping file paths to their corresponding analysis reports.
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_file = {executor.submit(
            process_file, fp): fp for fp in file_paths}
        for future in concurrent.futures.as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                results[file_path] = future.result()
            except Exception as exc:
                logger.error(f"{file_path} generated an exception: {exc}")
                results[file_path] = f"Error processing file: {exc}"
    return results


def main():
    """
    Main entry point for the analysis program.

    Parses command-line arguments and outputs the analysis report either to stdout or to an output file.
    """
    argparser = argparse.ArgumentParser(
        description="Advanced Static Analysis of C Source Code Files for Functions, Calls, Loops, Conditionals, and Variable Declarations."
    )
    argparser.add_argument(
        "files", nargs="+", help="List of C source code files to process.")
    argparser.add_argument(
        "-o", "--output", help="Optional output file to write the analysis report.")
    args = argparser.parse_args()

    analysis_results = analyze_multiple_files(args.files)

    combined_output = ""
    for file_path, report in analysis_results.items():
        combined_output += f"Analysis Report for {file_path}:\n"
        combined_output += report + "\n" + "=" * 80 + "\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as out_file:
                out_file.write(combined_output)
            logger.info(f"Analysis report written to {args.output}")
        except Exception as e:
            logger.error(f"Error writing to output file {args.output}: {e}")
    else:
        print(combined_output)


if __name__ == "__main__":
    main()

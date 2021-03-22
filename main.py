# coding=utf-8
import sys
from argparse import ArgumentParser
import importlib.util


def main():
    arg_parser = ArgumentParser(description='AWD Pwn Checker')
    arg_parser.add_argument('-t', '--timeout', type=int, default=10,
                            help='Timeout for check completion (default: 10)')
    arg_parser.add_argument('-H', '--host', type=str, help='Target host')
    arg_parser.add_argument('-p', '--port', type=int, help='Target port')
    arg_parser.add_argument('module', type=str,
                            help='Path of module to find checker script')
    args = arg_parser.parse_args()

    if not args.module:
        arg_parser.print_usage()
        sys.exit(1)
    try:
        module_spec = importlib.util.spec_from_file_location(
            "Checker", args.module)
        check_module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(check_module)

        ctx = check_module.Context(vars(args))
        check_result = check_module.Checker.check(ctx)

    except Exception as e:
        print(f"Exception: {e}")

    print(f"Check result for {args.module}:")
    print(check_result)


if __name__ == '__main__':
    main()

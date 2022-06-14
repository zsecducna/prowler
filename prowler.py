#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from lib.banner import print_banner, print_version
from lib.check import import_check, load_checks_to_execute, run_check
from lib.logger import logger, logging_levels
from providers.aws.aws_provider import provider_set_profile

if __name__ == "__main__":
    # CLI Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=["aws"], help="Specify Provider")
    parser.add_argument("-c", "--checks", nargs="+", help="List of checks")
    parser.add_argument(
        "-b", "--no-banner", action="store_false", help="Hide Prowler Banner"
    )
    parser.add_argument(
        "-v", "--version", action="store_true", help="Show Prowler version"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="ERROR",
        help="Select Log Level",
    )
    parser.add_argument(
        "-p",
        "--profile",
        nargs="?",
        const="default",
        help="AWS profile to launch prowler with",
    )
    # Parse Arguments
    args = parser.parse_args()
    provider = args.provider
    checks = args.checks
    profile = args.profile
    # Set Logger
    logger.setLevel(logging_levels.get(args.log_level))

    if args.version:
        print_version()
        quit()

    if args.no_banner:
        print_banner()

    # Setting profile
    provider_set_profile(profile)

    # Load checks to execute
    logger.debug("Loading checks")
    checks_to_execute = load_checks_to_execute(checks, provider)

    # Execute checks
    for check_name in checks_to_execute:
        # Recover service from check name
        service = check_name.split("_")[0]
        # Import check module
        check_module_path = (
            f"providers.{provider}.services.{service}.{check_name}.{check_name}"
        )
        try:
            lib = import_check(check_module_path)
            # Recover functions from check
            check_to_execute = getattr(lib, check_name)
            c = check_to_execute()
            # Run check
            run_check(c)

        # If check does not exists in the provider or is from another provider
        except ModuleNotFoundError:
            logger.error(
                f"Check '{check_name}' was not found for the {provider.upper()} provider"
            )

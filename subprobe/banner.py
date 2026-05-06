from colorama import Fore, Style

__version__ = "1.0.0"

BANNER = (
    f"\n{Fore.CYAN}"
    r"         _               _       " + "\n"
    f"{Fore.CYAN}" +
    r" ___ _ _| |_ ___ ___ ___| |_ ___ " + "\n"
    f"{Fore.CYAN}" +
    r"|_ -| | | . | . |  _| . | . | -_|" + "\n"
    f"{Fore.CYAN}" +
    r"|___|___|___|  _|_| |___|___|___|" + "\n"
    f"{Fore.CYAN}            |_| "
    f"{Fore.YELLOW}https://github.com/0xDrakon"
    f"{Fore.WHITE}                    v{__version__}"
    f"{Style.RESET_ALL}\n"
)

BANNER_PLAIN = (
    "\n"
    "         _               _       \n"
    " ___ _ _| |_ ___ ___ ___| |_ ___ \n"
    "|_ -| | | . | . |  _| . | . | -_|\n"
    "|___|___|___|  _|_| |___|___|___|\n"
    f"            |_| https://github.com/0xDrakon                    v{__version__}\n"
)

INFO_TAG  = f"{Fore.CYAN}[{Fore.WHITE}*{Fore.CYAN}]{Style.RESET_ALL}"
FOUND_TAG = f"{Fore.GREEN}[{Fore.WHITE}+{Fore.GREEN}]{Style.RESET_ALL}"
ERROR_TAG = f"{Fore.RED}[{Fore.WHITE}!{Fore.RED}]{Style.RESET_ALL}"
WARN_TAG  = f"{Fore.YELLOW}[{Fore.WHITE}~{Fore.YELLOW}]{Style.RESET_ALL}"
DONE_TAG  = f"{Fore.GREEN}[{Fore.WHITE}✔{Fore.GREEN}]{Style.RESET_ALL}"
HTTP_TAG  = f"{Fore.BLUE}[{Fore.WHITE}H{Fore.BLUE}]{Style.RESET_ALL}"

DIM   = "\033[2m"
RESET = Style.RESET_ALL


def status_color(code: int) -> str:
    if 200 <= code < 300:
        return Fore.GREEN
    elif 300 <= code < 400:
        return Fore.YELLOW
    elif 400 <= code < 500:
        return Fore.RED
    else:
        return Fore.MAGENTA


def dim(text: str) -> str:
    return f"{DIM}{text}{RESET}"


def sep(char: str = "─", width: int = 60, color: str = Fore.CYAN) -> str:
    return f"{color}{char * width}{RESET}"

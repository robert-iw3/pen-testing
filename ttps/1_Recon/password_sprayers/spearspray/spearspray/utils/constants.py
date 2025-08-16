AUTHOR = "sikumy"

BANNER = """
╔═╗┌─┐┌─┐┌─┐┬─┐╔═╗┌─┐┬─┐┌─┐┬ ┬
╚═╗├─┘├┤ ├─┤├┬┘╚═╗├─┘├┬┘├─┤└┬┘
╚═╝┴  └─┘┴ ┴┴└─╚═╝┴  ┴└─┴ ┴ ┴
"""

# Colors

CYAN = "\033[96m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BLACK = "\033[90m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

# LDAP

DEFAULT_LDAP_USERS_QUERY = (
    '(&'
    '(objectCategory=person)'
    '(objectClass=user)'
    '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' # Exclude disabled accounts
    '(!(userAccountControl:1.2.840.113556.1.4.803:=16))' # Exclude blocked accounts
    ')'
)

# Patterns variables

MONTH_NAMES_ES = {
    1: "Enero",	2: "Febrero", 3: "Marzo", 4: "Abril",
    5: "Mayo", 6: "Junio", 7: "Julio", 8: "Agosto",
    9: "Septiembre", 10: "Octubre",	11: "Noviembre", 12: "Diciembre"
}

MONTH_NAMES_EN = {
    1: "January", 2: "February", 3: "March", 4: "April",
    5: "May", 6: "June", 7: "July", 8: "August",
    9: "September", 10: "October", 11: "November", 12: "December"
}

SEASONS_ES = {
    1: "Invierno", 2: "Invierno", 3: "Primavera", 4: "Primavera",
    5: "Primavera", 6: "Verano", 7: "Verano", 8: "Verano",
    9: "Otoño", 10: "Otoño", 11: "Otoño", 12: "Invierno"
}

SEASONS_EN = {
    1: "Winter", 2: "Winter", 3: "Spring", 4: "Spring",
    5: "Spring", 6: "Summer", 7: "Summer", 8: "Summer",
    9: "Autumn", 10: "Autumn", 11: "Autumn", 12: "Winter"
}
from typing import List, Tuple

from outflank_stage1.task.base_bof_task import BaseBOFTask
from outflank_stage1.task.enums import BOFArgumentEncoding

class SekkenEnumBOF(BaseBOFTask):
    def __init__(self):
        super().__init__("sekken-enum", base_binary_name="sekken-enum")

        self.parser.description = "Active Directory Web Services (ADWS) enumeration BOF"
        self.parser.epilog = (
            "Enumerate Active Directory via ADWS protocol (TCP 9389).\n"
            "Example usage:\n"
            "  sekken-enum (objectClass=user)\n"
            "  sekken-enum (objectClass=user) samaccountname,objectsid\n"
            "  sekken-enum dc01.domain.local (objectClass=user) samaccountname,objectsid\n"
            "  sekken-enum dc01.domain.local (objectClass=*) -b CN=Configuration,DC=domain,DC=local\n"
            "Note: Target is optional - if omitted, DC will be auto-discovered via DsGetDcNameA.\n"
        )

        self.parser.add_argument(
            "target",
            nargs="?",
            default="",
            help="Target domain controller (e.g., 'dc01.domain.local'). If omitted, auto-discovers DC."
        )
        self.parser.add_argument(
            "filter",
            nargs="?",
            default="",
            help="LDAP filter (default: '(objectClass=*)')"
        )
        self.parser.add_argument(
            "attributes",
            nargs="?",
            default="",
            help="Comma-separated attributes to retrieve (default: all attributes)"
        )
        self.parser.add_argument(
            "-b", "--basedn",
            default="",
            help="Custom base DN (e.g., 'DC=domain,DC=local'). If not specified, auto-derives from user context or target."
        )

    def _encode_arguments_bof(self, arguments: List[str]) -> List[Tuple[BOFArgumentEncoding, str]]:
        parser_arguments = self.parser.parse_args(arguments)

        target = parser_arguments.target.strip('"').strip("'")
        filter_arg = parser_arguments.filter.strip('"').strip("'")
        attributes = parser_arguments.attributes.strip('"').strip("'")
        basedn = parser_arguments.basedn.strip('"').strip("'")

        bof_args = [
            (BOFArgumentEncoding.STR, target),
            (BOFArgumentEncoding.STR, filter_arg),
            (BOFArgumentEncoding.STR, attributes)
        ]

        if basedn:
            bof_args.append((BOFArgumentEncoding.STR, "-b"))
            bof_args.append((BOFArgumentEncoding.STR, basedn))

        return bof_args

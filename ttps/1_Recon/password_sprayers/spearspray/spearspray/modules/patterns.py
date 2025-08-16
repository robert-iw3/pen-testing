import questionary

from spearspray.utils.constants import RED, RESET

class Patterns:
    def __init__(self, extra: str, patterns_file: str):
        self.extra = extra
        self.patterns_file = patterns_file

    def has_comment(self, comment: str) -> bool:
        return comment is not None and comment != ""

    def read_patterns_file(self):
        patterns = []
        current_comment = None
        
        with open(self.patterns_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#'):
                    current_comment = line[1:].strip()
                else:
                    comment = current_comment if self.has_comment(current_comment) else line
                    patterns.append({
                        "comment": comment,
                        "pattern": line
                    })
                    current_comment = None  # Reset after using
        return patterns

    def create_dynamic_menu(self, patterns: list) -> str:
        
        choices = []
        for item in patterns:
            pattern = item["pattern"]
            
            uses_extra = "{extra}" in pattern
            if uses_extra and not self.extra:
                choices.append(
                    questionary.Choice(
                        title=f"❌ {item['comment']}",
                        value=pattern,
                        disabled="This pattern requires the extra argument (-x) to be set"
                    )
                )
            else:
                choices.append(
                    questionary.Choice(
                        title=f"- ✔  {item['comment']}",
                        value=item["pattern"]
                    )
                )

        selected_choice = questionary.select(
            "Select a pattern to use:",
            choices=choices
        ).ask(kbi_msg=f"\n{RED}[!] Process interrupted by user.{RESET}\n")
        
        if selected_choice is None:
            exit(130)  
            
        return selected_choice

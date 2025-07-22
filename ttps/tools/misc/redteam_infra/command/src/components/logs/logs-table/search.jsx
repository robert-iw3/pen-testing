import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export function DataTableSearch({ table, column, placeholder, className }) {
    return (
        <>
            <Input
                placeholder={placeholder}
                value={table.getColumn(column)?.getFilterValue() ?? ""}
                onChange={(event) => {
                    table.getColumn(column)?.setFilterValue(event.target.value);
                }}
                className={cn("max-w-sm max-lg:w-1/2", className)}
            />
        </>
    );
}

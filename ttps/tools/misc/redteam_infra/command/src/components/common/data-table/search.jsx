import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export function DataTableSearch({
  table,
  column,
  placeholder,
  className,
  setPagination,
}) {
  return (
    <>
      <Input
        placeholder={placeholder}
        value={table.getColumn(column)?.getFilterValue() ?? ""}
        onChange={(event) => {
          setPagination({
            pageIndex: 0,
            pageSize: 10,
          });
          table.getColumn(column)?.setFilterValue(event.target.value);
        }}
        className={cn("max-w-sm max-lg:w-1/2", className)}
      />
    </>
  );
}

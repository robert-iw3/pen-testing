import { cn } from "@/lib/utils";
import { cva } from "class-variance-authority";

const tagVariants = cva(
    "inline-flex py-0.5 px-1 text-xs uppercase rounded font-medium text-nowrap",
    {
        variants: {
            color: {
                gray: "bg-stone-500/10 text-stone-500",
                green: "bg-green-500/10 text-green-600",
                red: "bg-red-500/10 text-red-500",
                amber: "bg-amber-500/10 text-amber-500",
                purple: "bg-purple-500/10 text-purple-500",
                blue: "bg-blue-500/10 text-blue-500",
                orange: "bg-orange-500/10 text-orange-500",
                pink: "bg-pink-500/10 text-pink-500",
                teal: "bg-teal-500/10 text-teal-500",
            },
        },
        defaultVariants: {
            color: "gray",
        },
    },
);

export function Tag({ color, className, children }) {
    return (
        <div className={cn(tagVariants({ color, className }))}>{children}</div>
    );
}

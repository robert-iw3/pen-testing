"use client";

import { RefreshCw } from "lucide-react";

import { Button } from "../ui/button";
import { refreshData } from "@/actions/util";

export function RefreshButton() {
    return (
        <Button size="icon" variant="outline" onClick={() => refreshData()}>
            <RefreshCw />
        </Button>
    );
}

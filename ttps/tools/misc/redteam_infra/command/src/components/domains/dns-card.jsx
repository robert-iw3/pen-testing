"use client";

import { cn } from "@/lib/utils";
import {
    Card,
    CardHeader,
    CardTitle,
    CardContent,
    CardDescription,
} from "../ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "../ui/button";
import { useState } from "react";
import { Settings } from "lucide-react";
import { DataTable } from "../common/data-table/data-table";
import { dnsColumns } from "./columns";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";
import { Checkbox } from "../ui/checkbox";
import { updateDnsAutoScan } from "@/actions/domains";
import { CreateDNS } from "./create-dns";

export function DNSCard({ className, domain, dnsRecords }) {
    const aRecords = dnsRecords.filter((record) => record.type === "a");
    const aaaaRecords = dnsRecords.filter((record) => record.type === "aaaa");
    const cnameRecords = dnsRecords.filter((record) => record.type === "cname");
    const mxRecords = dnsRecords.filter((record) => record.type === "mx");
    const nsRecords = dnsRecords.filter((record) => record.type === "ns");
    const ptrRecords = dnsRecords.filter((record) => record.type === "ptr");
    const soaRecords = dnsRecords.filter((record) => record.type === "soa");
    const srvRecords = dnsRecords.filter((record) => record.type === "srv");
    const txtRecords = dnsRecords.filter((record) => record.type === "txt");

    const [isOpen, setIsOpen] = useState(false);
    const [dnsAutoScan, setDnsAutoScan] = useState(domain?.dnsAutoScan);
    const [valueChanged, setValueChanged] = useState(false);

    const handleAutoScanChange = (value) => {
        setDnsAutoScan(value);
        setValueChanged(true);
    };

    const handleSubmit = async () => {
        updateDnsAutoScan(domain.id, dnsAutoScan);
        setIsOpen(false);
    };

    let latestRecord = "Never";

    if (dnsRecords.length > 0) {
        latestRecord = dnsRecords.reduce((latest, item) => {
            return new Date(item.updated) > new Date(latest.updated)
                ? item
                : latest;
        });
    }

    return (
        <Card className={cn(className)}>
            <CardHeader className="flex flex-row items-center justify-between">
                <div>
                    <CardTitle>DNS Records</CardTitle>
                    <CardDescription
                        className="text-xs text-muted-foreground mt-1.5"
                        suppressHydrationWarning
                    >
                        Updated:{" "}
                        {latestRecord.updated
                            ? new Date(latestRecord.updated).toISOString()
                            : "Never"}
                    </CardDescription>
                </div>
                <div
                    className="flex items-center gap-2"
                    style={{ marginTop: 0 }}
                >
                    <Dialog open={isOpen} onOpenChange={setIsOpen}>
                        <DialogTrigger asChild>
                            <div
                                className="flex items-center"
                                style={{ marginTop: 0 }}
                            >
                                <Button
                                    size="icon"
                                    className="h-9"
                                    variant="outline"
                                >
                                    <Settings className="h-4" />
                                </Button>
                            </div>
                        </DialogTrigger>
                        <DialogContent>
                            <DialogHeader>
                                <DialogTitle>DNS Record Settings</DialogTitle>
                                <DialogDescription>
                                    Modify the DNS record settings for a domain.
                                </DialogDescription>
                            </DialogHeader>
                            <div className="grid gap-4 py-4">
                                <div className="items-top flex space-x-2">
                                    <Checkbox
                                        id="autoscan"
                                        checked={dnsAutoScan}
                                        onCheckedChange={handleAutoScanChange}
                                    />
                                    <div className="grid gap-1.5 leading-none">
                                        <label
                                            htmlFor="autoscan"
                                            className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
                                        >
                                            Enable Auto Scan
                                        </label>
                                        <p className="text-sm text-muted-foreground">
                                            Automatically fetch DNS records for
                                            a domain.
                                            <br />
                                            Warning, this option will override
                                            any custom records.
                                        </p>
                                    </div>
                                </div>
                            </div>
                            <DialogFooter>
                                <Button
                                    disabled={!valueChanged}
                                    onClick={() => {
                                        handleSubmit();
                                    }}
                                >
                                    Save
                                </Button>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                    {domain.dnsAutoScan ? (
                        // TODO: Button can't be child of tooltip
                        <TooltipProvider delayDuration={0}>
                            <Tooltip>
                                <TooltipTrigger className="cursor-not-allowed">
                                    <Button size="sm" disabled>
                                        Add
                                    </Button>
                                </TooltipTrigger>
                                <TooltipContent>
                                    <p>Disable auto scan first</p>
                                </TooltipContent>
                            </Tooltip>
                        </TooltipProvider>
                    ) : (
                        <CreateDNS domainId={domain.id} />
                    )}
                </div>
            </CardHeader>
            <CardContent>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Tabs defaultValue="a" className="">
                            <TabsList>
                                <TabsTrigger value="a">A</TabsTrigger>
                                <TabsTrigger value="aaaa">AAAA</TabsTrigger>
                                <TabsTrigger value="cname">CNAME</TabsTrigger>
                                <TabsTrigger value="mx">MX</TabsTrigger>
                                <TabsTrigger value="ns">NS</TabsTrigger>
                                <TabsTrigger value="ptr">PTR</TabsTrigger>
                                <TabsTrigger value="soa">SOA</TabsTrigger>
                                <TabsTrigger value="srv">SRV</TabsTrigger>
                                <TabsTrigger value="txt">TXT</TabsTrigger>
                            </TabsList>
                            <TabsContent value="a" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={aRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="aaaa" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={aaaaRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="cname" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={cnameRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="mx" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={mxRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="ns" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={nsRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="ptr" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={ptrRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="soa" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={soaRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="srv" className="h-full">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={srvRecords}
                                    />
                                </div>
                            </TabsContent>
                            <TabsContent value="txt">
                                <div>
                                    <DataTable
                                        columns={dnsColumns}
                                        data={txtRecords}
                                    />
                                </div>
                            </TabsContent>
                        </Tabs>
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}

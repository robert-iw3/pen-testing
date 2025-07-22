"use client";

import { cn } from "@/lib/utils";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardFooter,
  CardDescription,
} from "../ui/card";
import { Tag } from "../common/tag";
import { Settings } from "lucide-react";
import { Checkbox } from "../ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "../ui/button";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "../ui/label";
import { useState } from "react";
import { changeHealthSettings } from "@/actions/domains";

export function HealthCard({ className, domain }) {
  const [isOpen, setIsOpen] = useState(false);

  const [state, setState] = useState(domain?.state);
  const [stateAutoScan, setStateAutoScan] = useState(domain?.stateAutoScan);

  const [valueChanged, setValueChanged] = useState(false);

  const handleStateChange = (value) => {
    setState(value);
    setValueChanged(true);
  };

  const handleAutoScanChange = (value) => {
    setStateAutoScan(value);
    setValueChanged(true);
  };

  const handleSubmit = async () => {
    changeHealthSettings(domain.id, stateAutoScan, state);
    if (stateAutoScan) setState("pending-analysis");
    setIsOpen(false);
  };

  return (
    <Card className={cn(className)}>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle>Health Overview</CardTitle>
          <CardDescription
            className="text-xs text-muted-foreground mt-1.5"
            suppressHydrationWarning
          >
            Updated:{" "}
            {domain.stateUpdated
              ? new Date(domain.stateUpdated).toISOString()
              : "Never"}
          </CardDescription>
        </div>
        <Dialog open={isOpen} onOpenChange={setIsOpen}>
          <DialogTrigger asChild>
            <div className="flex items-center" style={{ marginTop: 0 }}>
              <Button size="icon" className="h-9" variant="outline">
                <Settings className="h-4" />
              </Button>
            </div>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Domain Health Settings</DialogTitle>
              <DialogDescription>
                Modify the health settings for a domain.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="items-top flex space-x-2">
                <Checkbox
                  id="autoscan"
                  checked={stateAutoScan}
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
                    Automatically scan the domain for health issues.
                  </p>
                </div>
              </div>
              <div className="grid gap-2">
                <Label>State</Label>
                <Select
                  defaultValue={state}
                  onValueChange={handleStateChange}
                  disabled={stateAutoScan}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select a state" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="pending-analysis">
                        <Tag color={"purple"}>pending-analysis</Tag>
                      </SelectItem>
                      <SelectItem value="healthy">
                        <Tag color={"green"}>healthy</Tag>
                      </SelectItem>
                      <SelectItem value="unhealthy">
                        <Tag color={"amber"}>unhealthy</Tag>
                      </SelectItem>
                      <SelectItem value="burnt">
                        <Tag color={"red"}>burnt</Tag>
                      </SelectItem>
                      <SelectItem value="aging">
                        <Tag color={"blue"}>aging</Tag>
                      </SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
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
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-2">
          <p className="text-sm">
            {domain.description
              ? domain.description
              : "No issues have been identified with this domain."}
          </p>
        </div>
      </CardContent>
      <CardFooter className="flex flex-row gap-2">
        {(() => {
          switch (domain?.state) {
            case "pending-analysis":
              return (
                <Tag className="self-start" color={"purple"}>
                  {domain?.state}
                </Tag>
              );
            case "healthy":
              return (
                <Tag className="self-start" color={"green"}>
                  {domain?.state}
                </Tag>
              );
            case "burnt":
              return (
                <Tag className="self-start" color={"red"}>
                  {domain?.state}
                </Tag>
              );
            case "aging":
              return (
                <Tag className="self-start" color={"blue"}>
                  {domain?.state}
                </Tag>
              );
            case "archived":
              return (
                <Tag className="self-start" color={"gray"}>
                  {domain?.state}
                </Tag>
              );
          }
        })()}
      </CardFooter>
    </Card>
  );
}

"use client";

import { Button } from "@/components/ui/button";
import { useState } from "react";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
    DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { saveAs } from "file-saver";

import { addKey } from "@/actions/keys";

export function CreateKey() {
    const [dialogOpen, setDialogOpen] = useState(false);

    const [name, setName] = useState("");
    const [nameError, setNameError] = useState(false);

    const [fileName, setFileName] = useState("");

    const [isLoading, setIsLoading] = useState(false);

    const [showDownload, setShowDownload] = useState(false);

    const [privateKey, setPrivateKey] = useState("");

    const addKeyHandler = async () => {
        if (!name) return setNameError(true);
        setIsLoading(true);

        const result = await addKey(name);
        if (result !== null) {
            setFileName(name);
            setName("");
            setIsLoading(false);
            setPrivateKey(result);
            setNameError(false);
            setShowDownload(true);
        }
    };

    const keyDownloadHandler = () => {
        const privateKeyBlob = new Blob([privateKey], {
            type: "application/x-pem-file;charset=utf-8",
        });

        saveAs(privateKeyBlob, `${fileName}.pem`);
    };

    const setDialogOpenHandler = (value) => {
        setDialogOpen(value);
        if (!value) setShowDownload(false);
    };

    return (
        <Dialog open={dialogOpen} onOpenChange={setDialogOpenHandler}>
            <DialogTrigger asChild>
                <Button>Create Key</Button>
            </DialogTrigger>
            <DialogContent>
                {!showDownload ? (
                    <>
                        <DialogHeader>
                            <DialogTitle>Create SSH Key</DialogTitle>
                            <DialogDescription>
                                Complete the form below to create a new SSH key.
                                Required fields are marked with an asterisk.
                            </DialogDescription>
                        </DialogHeader>
                        <div className="grid gap-4">
                            <div className="grid gap-2">
                                <Label htmlFor="name">Name*</Label>
                                <Input
                                    id="name"
                                    placeholder="C2 Servers"
                                    value={name}
                                    className={
                                        nameError ? "border border-red-500" : ""
                                    }
                                    onChange={(e) => setName(e.target.value)}
                                />
                            </div>
                        </div>
                        <DialogFooter>
                            <Button
                                type="button"
                                disabled={name == "" || isLoading}
                                onClick={() => addKeyHandler()}
                            >
                                Create
                            </Button>
                        </DialogFooter>
                    </>
                ) : (
                    <>
                        <DialogHeader>
                            <DialogTitle>Download Private Key</DialogTitle>
                            <DialogDescription>
                                Download your private key. Once you close this
                                dialog you can&apos;t download it again!
                            </DialogDescription>
                        </DialogHeader>
                        <div className="grid gap-4">
                            <div className="grid gap-2">
                                <Button onClick={() => keyDownloadHandler()}>
                                    Download
                                </Button>
                            </div>
                        </div>
                    </>
                )}
            </DialogContent>
        </Dialog>
    );
}

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
import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectLabel,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";

import { addUser } from "@/actions/users";

export function CreateUser() {
    const [dialogOpen, setDialogOpen] = useState(false);

    const [name, setName] = useState("");
    const [nameError, setNameError] = useState(false);

    const [email, setEmail] = useState("");
    const [emailError, setEmailError] = useState(false);

    const [role, setRole] = useState("");
    const [roleError, setRoleError] = useState(false);

    const [password, setPassword] = useState("");
    const [passwordError, setPasswordError] = useState(false);

    const [confirmPassword, setConfirmPassword] = useState("");
    const [confirmPasswordError, setConfirmPasswordError] = useState(false);

    const addUserHandler = async () => {
        if (!email) return setEmailError(true);
        if (!name) return setNameError(true);
        if (!role) return setRoleError(true);

        if (!/^[\w-+#\.]+@([\w-]+\.)+[\w-]{2,5}$/.test(email))
            return setEmailError(true);

        if (!password) return setPasswordError(true);
        if (!confirmPassword) return setConfirmPasswordError(true);
        if (password !== confirmPassword) return setConfirmPasswordError(true);

        const result = await addUser(
            name,
            email,
            role,
            password,
            confirmPassword,
        );
        if (result) {
            setName("");
            setEmail("");
            setRole("");
            setPassword("");
            setConfirmPassword("");
            setNameError(false);
            setEmailError(false);
            setRoleError(false);
            setPasswordError(false);
            setConfirmPasswordError(false);
            setDialogOpen(false);
        }
    };

    return (
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
                <Button>Create User</Button>
            </DialogTrigger>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Create User</DialogTitle>
                    <DialogDescription>
                        Complete the form below to create a new user. Required
                        fields are marked with an asterisk.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4">
                    <div className="grid gap-2">
                        <Label htmlFor="name">Name*</Label>
                        <Input
                            id="name"
                            placeholder="John Doe"
                            value={name}
                            className={nameError ? "border border-red-500" : ""}
                            onChange={(e) => setName(e.target.value)}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="email">Email*</Label>
                        <Input
                            id="email"
                            placeholder="john.doe@lodestar-forge.local"
                            value={email}
                            type="email"
                            className={
                                emailError ? "border border-red-500" : ""
                            }
                            onChange={(e) => setEmail(e.target.value)}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="role">Role*</Label>
                        <Select value={role} onValueChange={setRole}>
                            <SelectTrigger>
                                <SelectValue placeholder="Select a role" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    <SelectLabel>Roles</SelectLabel>
                                    <SelectItem value="admin">Admin</SelectItem>
                                    <SelectItem value="operator">
                                        Operator
                                    </SelectItem>
                                    <SelectItem value="readonly">
                                        Read Only
                                    </SelectItem>
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="password">Password*</Label>
                        <Input
                            id="password"
                            placeholder="••••••••••••"
                            value={password}
                            type="password"
                            className={
                                passwordError ? "border border-red-500" : ""
                            }
                            onChange={(e) => setPassword(e.target.value)}
                        />
                    </div>
                    <div className="grid gap-2">
                        <Label htmlFor="confirm-password">
                            Confirm Password*
                        </Label>
                        <Input
                            id="confirm-password"
                            placeholder="••••••••••••"
                            value={confirmPassword}
                            type="password"
                            className={
                                confirmPasswordError
                                    ? "border border-red-500"
                                    : ""
                            }
                            onChange={(e) => setConfirmPassword(e.target.value)}
                        />
                    </div>
                </div>
                <DialogFooter>
                    <div className="w-full flex flex-row justify-between items-center">
                        <p className="text-sm text-red-500">
                            {emailError ? "Enter a valid email address." : ""}
                            {confirmPasswordError
                                ? "Passwords do not match."
                                : ""}
                        </p>
                        <Button
                            type="button"
                            disabled={
                                email == "" ||
                                name == "" ||
                                role == "" ||
                                password == "" ||
                                confirmPassword == ""
                            }
                            onClick={() => addUserHandler()}
                        >
                            Create
                        </Button>
                    </div>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

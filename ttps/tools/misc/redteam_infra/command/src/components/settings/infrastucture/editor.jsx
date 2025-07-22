"use client";

import Editor from "react-simple-code-editor";
import { highlight, languages } from "prismjs/components/prism-core";
import "prismjs/components/prism-hcl";
import "prismjs/themes/prism-tomorrow.min.css";

export const HclEditor = ({ code, setCode }) => {
    return (
        <div className="h-[200px] overflow-auto border rounded-md px-3 py-2">
            <Editor
                value={code}
                onValueChange={(code) => setCode(code)}
                highlight={(code) => highlight(code, languages.hcl)}
                placeholder={`# Basic Instance
resource "aws_instance" "basic" {
  ami                         = "ami-0e2c8caa4b6378d8c"
  instance_type               = "t2.micro"
  vpc_security_group_ids      = [aws_security_group.my_security_group.id]
  subnet_id                   = aws_subnet.private_subnet.id
  associate_public_ip_address = true

  tags = {
    Name = "Short C2"
  }
}`}
                className="font-mono min-h-[200px] text-sm focus:border-none focus:outline-none focus:ring-0"
            />
        </div>
    );
};

"use client";

import Editor from "react-simple-code-editor";
import { highlight, languages } from "prismjs/components/prism-core";
import "prismjs/components/prism-yaml";
import "prismjs/themes/prism-tomorrow.min.css";

export const YamlEditor = ({ code, setCode }) => {
    return (
        <div className="h-[250px] overflow-auto border border-1 rounded-md px-3 py-2">
            <Editor
                value={code}
                onValueChange={(code) => setCode(code)}
                highlight={(code) => highlight(code, languages.yaml)}
                placeholder={`# Nginx Install
tasks:
  - name: Install required system packages
    apt:
      pkg:
        - nginx
      state: latest
      update_cache: true

  - name: Configuring nginx
    copy:
      src: $$nginxConfigFile$$
      dest: /etc/nginx/sites-enabled/default

  - name: Restarting nginx
    ansible.builtin.service:
      name: nginx
      state: restarted
`}
                className="font-mono min-h-[250px] text-sm"
            />
        </div>
    );
};

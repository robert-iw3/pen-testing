"use client";

import Editor from "react-simple-code-editor";
import { highlight, languages } from "prismjs/components/prism-core";
import "prismjs/themes/prism-tomorrow.min.css";

export const FileEditor = ({ code, setCode }) => {
    return (
        <div className="h-[200px] overflow-auto border border-1 rounded-md px-3 py-2">
            <Editor
                value={code}
                onValueChange={(code) => setCode(code)}
                highlight={(code) => code}
                placeholder={`server {
  listen 80 default_server;

  server_name $$publicIp$$;
  keepalive_timeout 70;
  client_max_body_size 2M;

  location ^~ / {
    proxy_pass $$forwardDomain$$;
  }

  location ^~ $$redirectPath$$ {
    proxy_pass http://$$c2Ip$$;
  }
}`}
                className="font-mono min-h-[200px] text-sm"
            />
        </div>
    );
};

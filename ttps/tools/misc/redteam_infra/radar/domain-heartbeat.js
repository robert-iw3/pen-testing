import { db } from "./db";
import { domains } from "./schema/domains";
import { eq } from "drizzle-orm";

const domainHeartbeat = async () => {
  const data = await db.select().from(domains);
  if (data.length > 0) {
    await Promise.all(
      data.map(async (domain) => {
        let online = null;

        try {
          // Make a request to domain to determine status
          await fetch(`http://${domain.domain}`);
          online = true;
        } catch (e) {
          online = false;
        }

        if (!online) {
          try {
            // Make a request to domain to determine status
            await fetch(`https://${domain.domain}`);
            online = true;
          } catch (e) {
            online = false;
          }
        }

        // Update DB
        await db
          .update(domains)
          .set({
            online,
            updated: new Date(),
          })
          .where(eq(domains.id, domain.id));
      }),
    );

    return process.exit();
  }
};

domainHeartbeat();

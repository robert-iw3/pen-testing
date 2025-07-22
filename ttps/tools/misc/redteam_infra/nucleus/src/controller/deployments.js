import { db } from "../db/index.js";
import { and, eq, inArray, ne } from "drizzle-orm";
import { execSync, spawn } from "child_process";
import { parseKey } from "sshpk";
import fs from "fs";
import path from "path";
import { readFile } from "fs/promises";
import { quickCreateLog } from "./logs.js";
import yaml from "js-yaml";

// Import terraform templates
import { awsMain } from "../templates/system/aws/main.tf.js";
import { awsNetwork } from "../templates/system/aws/network.tf.js";
import { awsKey } from "../templates/system/aws/key.tf.js";
import { doMain } from "../templates/system/digitalocean/main.tf.js";
import { doNetwork } from "../templates/system/digitalocean/network.tf.js";
import { doKey } from "../templates/system/digitalocean/key.tf.js";

// import database schemas
import { integrations } from "../db/schema/integrations.js";
import { deployments } from "../db/schema/deployments.js";
import { sshKeys } from "../db/schema/sshKeys.js";
import { infrastructure } from "../db/schema/infrastructure.js";
import { resources } from "../db/schema/resources.js";
import { templates } from "../db/schema/templates.js";
import { files } from "../db/schema/files.js";
import { settings } from "../db/schema/settings.js";

// Constants
const DEFAULT_PATH =
  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const DEPLOYMENTS_DIR = "/app/deployments";

// Function to add to deployment log
const addToDeploymentLog = async (deploymentId, data) => {
  const [logData] = await db
    .select({ log: deployments.log })
    .from(deployments)
    .where(eq(deployments.id, deploymentId));

  const log =
    !logData?.log || logData.log === "null" ? data : logData.log + data;

  await db
    .update(deployments)
    .set({ log })
    .where(eq(deployments.id, deploymentId));
};

// Function to handle running commands
const runCommand = (deploymentId, projectId, command, args, env, cwd) => {
  return new Promise((resolve, reject) => {
    const process = spawn(command, args, { cwd, env });
    let fullLog = "";

    const handleData = async (data) => {
      await addToDeploymentLog(deploymentId, data);
      fullLog += data;
    };

    process.stdout.on("data", handleData);
    process.stderr.on("data", handleData);

    process.on("close", (code) => {
      const source = command.includes("terraform")
        ? "terraform"
        : command.includes("tailscale")
          ? "tailscale"
          : command.includes("ansible")
            ? "ansible"
            : "nucleus";

      quickCreateLog({
        message: fullLog,
        projectId,
        source,
        status: code === 0 ? "info" : "error",
        resource: deploymentId,
      });

      code === 0 ? resolve(true) : reject(false);
    });
  });
};

// Handle configuration variables
const handleConfigurationVariables = async (template, variables, filesDir) => {
  for (const variable of variables) {
    if (variable.type === "file" && filesDir) {
      const [fileData] = await db
        .select()
        .from(files)
        .where(eq(files.id, variable.value));

      let fileContent = fileData.value;

      if (variable?.variables?.length > 0) {
        fileContent = await handleConfigurationVariables(
          fileData.value,
          variable.variables,
        );
      }

      const filePath = path.join(
        filesDir,
        `${fileData.id}.${fileData.extension}`,
      );

      fs.writeFileSync(filePath, fileContent, "utf-8");

      template = template.replaceAll(`$$${variable.name}$$`, filePath);
    } else {
      template = template.replaceAll(`$$${variable.name}$$`, variable.value);
    }
  }

  return template;
};

// Function to add a host to a playbook
const addHostToPlaybook = (hostname, playbookYaml) => {
  const playbook = yaml.load(playbookYaml);
  playbook[0].hosts = hostname;
  return yaml.dump(playbook);
};

export const allDeployments = async (req, res) => {
  const { projectId } = req.query;

  const integrationRows = await db
    .select({ id: integrations.id, platform: integrations.platform })
    .from(integrations);

  const rows = await db
    .select()
    .from(deployments)
    .where(projectId ? eq(deployments.projectId, projectId) : undefined);

  const rowsWithPlatform = rows.map((row) => {
    const integration = integrationRows.find((i) => i.id === row.platformId);
    return {
      ...row,
      platform: integration?.platform,
    };
  });

  return res.status(200).json(rowsWithPlatform);
};

export const createDeployment = async (req, res) => {
  try {
    const {
      name,
      description,
      sshKeyId,
      platformId,
      projectId,
      tailscaleId,
      region,
    } = req.body;

    // Validate required fields
    const requiredFields = {
      name: "'name' is required.",
      sshKeyId: "'sshKeyId' is required.",
      platformId: "'platformId' is required.",
      tailscaleId: "'tailscaleId' is required.",
      projectId: "'projectId' is required.",
      region: "'region' is required.",
    };

    for (const [field, message] of Object.entries(requiredFields)) {
      if (!req.body[field]) {
        return res.status(400).json({ error: message });
      }
    }

    const [result] = await db
      .insert(deployments)
      .values({
        name,
        description,
        sshKeyId,
        platformId,
        projectId,
        tailscaleId,
        region,
      })
      .returning();

    if (result) {
      quickCreateLog({
        message: `User ${res.locals.user.id} (${res.locals.user.name}) created the deployment ${result.id} (${result.name}).`,
        projectId,
        source: "nucleus",
        status: "info",
        resource: result.id,
      });
      return res.status(200).json(result);
    }

    throw new Error("Failed to create deployment");
  } catch (e) {
    quickCreateLog({
      message: e.message,
      projectId,
      source: "nucleus",
      status: "error",
      resource: projectId,
    });
    return res.status(500).json({
      error:
        "An unknown error occurred, please check the activity log for more details.",
    });
  }
};

export const deleteDeployment = async (req, res) => {
  const { deploymentId } = req.params;
  if (!deploymentId) {
    return res.status(400).json({ error: "error 'deploymentId' is required" });
  }

  try {
    const [deploymentData] = await db
      .update(deployments)
      .set({ status: "destroying" })
      .where(eq(deployments.id, deploymentId))
      .returning();

    if (!deploymentData) {
      return res.status(404).json({ error: "Deployment not found" });
    }

    res.sendStatus(200);

    const [platform] = await db
      .select()
      .from(integrations)
      .where(eq(integrations.id, deploymentData.platformId));

    const envVars = {
      TF_CLI_ARGS: "-no-color",
      PATH: DEFAULT_PATH,
    };

    if (platform.platform === "aws") {
      envVars.AWS_ACCESS_KEY_ID = String(platform.keyId);
      envVars.AWS_SECRET_ACCESS_KEY = String(platform.secretKey);
    } else if (platform.platform === "digitalocean") {
      envVars.DIGITALOCEAN_TOKEN = String(platform.secretKey);
    }

    const deploymentDir = path.join(DEPLOYMENTS_DIR, deploymentData.id);
    const terraformDir = path.join(deploymentDir, "terraform");

    if (
      fs.existsSync(terraformDir) &&
      fs.existsSync(path.join(terraformDir, "terraform.tfstate"))
    ) {
      try {
        await runCommand(
          deploymentId,
          deploymentData.projectId,
          "terraform",
          ["apply", "-destroy", "-auto-approve"],
          envVars,
          terraformDir,
        );
      } catch (e) {
        console.error(e);
        await db
          .update(deployments)
          .set({ status: "failed" })
          .where(eq(deployments.id, deploymentId));
      }
    }

    if (fs.existsSync(path.join(DEPLOYMENTS_DIR, deploymentId))) {
      fs.rmSync(path.join(DEPLOYMENTS_DIR, deploymentId), {
        recursive: true,
      });
    }

    const [deleted] = await db
      .delete(deployments)
      .where(eq(deployments.id, deploymentId))
      .returning();

    quickCreateLog({
      message: `User ${res.locals.user.id} (${res.locals.user.name}) deleted the deployment ${deleted.id} (${deleted.name}).`,
      projectId: deleted.projectId,
      source: "nucleus",
      status: "info",
      resource: deleted.id,
    });
  } catch (e) {
    const [updated] = await db
      .update(deployments)
      .set({ status: "failed" })
      .where(eq(deployments.id, deploymentId))
      .returning();

    quickCreateLog({
      message: e.message,
      projectId: updated.projectId,
      source: "nucleus",
      status: "error",
      resource: updated.id,
    });

    console.error(e);
  }
};

export const prepareDeployment = async (req, res) => {
  const { deploymentId } = req.params;
  const infrastructureId = String(crypto.randomUUID());

  if (!deploymentId) {
    return res.status(400).json({ error: "error 'deploymentId' is required" });
  }

  const [deploymentData] = await db
    .select()
    .from(deployments)
    .where(eq(deployments.id, deploymentId));

  if (!deploymentData) {
    return res.status(404).json({ error: "Deployment not found" });
  }

  const [keyData] = await db
    .select()
    .from(sshKeys)
    .where(eq(sshKeys.id, deploymentData.sshKeyId));

  if (!keyData) {
    return res.status(404).json({ error: "SSH key not found" });
  }

  await db
    .update(deployments)
    .set({ status: "preparing" })
    .where(eq(deployments.id, deploymentId));

  res.sendStatus(200);

  const [platform] = await db
    .select()
    .from(integrations)
    .where(eq(integrations.id, deploymentData.platformId));

  const deploymentDir = path.join(DEPLOYMENTS_DIR, deploymentId);
  const terraformDir = path.join(deploymentDir, "terraform");
  const ansibleDir = path.join(deploymentDir, "ansible");
  const filesDir = path.join(deploymentDir, "files");

  // Create folder structure
  [deploymentDir, terraformDir, ansibleDir, filesDir].forEach((dir) => {
    fs.mkdirSync(dir, { recursive: true });
  });

  if (platform.platform === "aws") {
    fs.writeFileSync(
      path.join(terraformDir, "main.tf"),
      awsMain({ region: deploymentData.region }),
      "utf8",
    );

    fs.writeFileSync(
      path.join(terraformDir, "network.tf"),
      awsNetwork({ deploymentId: deploymentData.id }),
      "utf8",
    );

    const pemKey = parseKey(keyData.public, "pem");
    const sshRsa = pemKey.toString("ssh");

    fs.writeFileSync(
      path.join(terraformDir, "key.tf"),
      awsKey({
        deploymentId,
        publicKey: sshRsa,
        keyName: keyData.name,
      }),
      "utf8",
    );
  } else if (platform.platform === "digitalocean") {
    fs.writeFileSync(path.join(terraformDir, "main.tf"), doMain(), "utf8");

    fs.writeFileSync(
      path.join(terraformDir, "network.tf"),
      doNetwork({
        deploymentId: deploymentData.id,
        region: deploymentData.region,
      }),
      "utf8",
    );

    const pemKey = parseKey(keyData.public, "pem");
    const sshRsa = pemKey.toString("ssh");

    fs.writeFileSync(
      path.join(terraformDir, "key.tf"),
      doKey({
        deploymentId: deploymentData.id,
        publicKey: sshRsa,
        keyName: keyData.name,
      }),
      "utf8",
    );
  }

  fs.writeFileSync(
    path.join(deploymentDir, "private-key.pem"),
    keyData.private,
    { mode: 0o600 },
  );

  const envVars = {
    TF_CLI_ARGS: "-no-color",
    PATH: DEFAULT_PATH,
  };

  if (platform.platform === "aws") {
    envVars.AWS_ACCESS_KEY_ID = String(platform.keyId);
    envVars.AWS_SECRET_ACCESS_KEY = String(platform.secretKey);
  } else if (platform.platform === "digitalocean") {
    envVars.DIGITALOCEAN_TOKEN = String(platform.secretKey);
  }

  try {
    await runCommand(
      deploymentId,
      deploymentData.projectId,
      "terraform",
      ["init"],
      envVars,
      terraformDir,
    );

    await runCommand(
      deploymentId,
      deploymentData.projectId,
      "terraform",
      ["apply", "-auto-approve"],
      envVars,
      terraformDir,
    );

    await db.update(deployments).set({ status: "ready-to-deploy" });

    await db.insert(infrastructure).values({
      id: infrastructureId,
      deploymentId,
      name: "Forge - Default Infrastructure",
      description:
        "The default deployment network and resources created by Lodestar Forge.",
      status: "default",
    });

    const state = JSON.parse(
      await readFile(path.join(terraformDir, "terraform.tfstate"), "utf8"),
    );

    const newResources = state.resources.map((resource) => ({
      infrastructureId,
      resourceName: resource.name,
      resourceType: resource.type,
      providerId: resource.instances[0].attributes.id,
      privateIp:
        resource.instances[0].attributes.private_ip ||
        resource.instances[0].attributes.cidr_block ||
        resource.instances[0].attributes.ip_range ||
        null,
      publicIp: resource.instances[0].attributes.public_ip || null,
    }));

    if (newResources.length) {
      await db.insert(resources).values(newResources);
    }
  } catch {
    await db
      .update(deployments)
      .set({ status: "failed" })
      .where(eq(deployments.id, deploymentId));
  }
};

export const deployDeployment = async (req, res) => {
  const { deploymentId } = req.params;

  if (!deploymentId) {
    return res.status(400).json({ error: "error 'deploymentId' is required" });
  }

  const deploymentData = await db.transaction(async (tx) => {
    const [original] = await db
      .select()
      .from(deployments)
      .where(eq(deployments.id, deploymentId));

    const [updated] = await db
      .update(deployments)
      .set({ status: "deploying" })
      .where(eq(deployments.id, deploymentId))
      .returning();

    return { original, updated };
  });

  if (!deploymentData.original) {
    return res.status(404).json({ error: "Deployment not found" });
  }

  if (deploymentData.original.status === "deploying") {
    return res.status(400).json({ error: "Deployment is already deploying" });
  }

  await db
    .update(infrastructure)
    .set({ status: "building" })
    .where(
      and(
        inArray(infrastructure.status, ["pending", "failed"]),
        eq(infrastructure.deploymentId, deploymentId),
      ),
    );

  res.sendStatus(200);

  const [platform] = await db
    .select()
    .from(integrations)
    .where(eq(integrations.id, deploymentData.original.platformId));

  const envVars = {
    TF_CLI_ARGS: "-no-color",
    PATH: DEFAULT_PATH,
  };

  if (platform.platform === "aws") {
    envVars.AWS_ACCESS_KEY_ID = String(platform.keyId);
    envVars.AWS_SECRET_ACCESS_KEY = String(platform.secretKey);
  } else if (platform.platform === "digitalocean") {
    envVars.DIGITALOCEAN_TOKEN = String(platform.secretKey);
  }

  const deploymentDir = path.join(DEPLOYMENTS_DIR, deploymentId);
  const terraformDir = path.join(deploymentDir, "terraform");

  try {
    // Format terraform files to prevent issues
    await runCommand(
      deploymentId,
      deploymentData.original.projectId,
      "terraform",
      ["fmt"],
      { TF_CLI_ARGS: "-no-color" },
      terraformDir,
    );

    await runCommand(
      deploymentId,
      deploymentData.original.projectId,
      "terraform",
      ["apply", "-auto-approve"],
      envVars,
      terraformDir,
    );

    const state = JSON.parse(
      await readFile(path.join(terraformDir, "terraform.tfstate"), "utf8"),
    );

    const stateResources = state.resources;

    const infrastructureRows = await db
      .select()
      .from(infrastructure)
      .where(
        and(
          eq(infrastructure.deploymentId, deploymentId),
          ne(infrastructure.status, "default"),
        ),
      );

    for (const infrastructureRow of infrastructureRows) {
      try {
        const resourceRows = await db
          .select()
          .from(resources)
          .where(eq(resources.infrastructureId, infrastructureRow.id));

        let username = "";
        for (const resourceRow of resourceRows) {
          const stateResource = stateResources.find(
            (r) => r.name === resourceRow.resourceName,
          );

          const amiId = stateResource.instances[0].attributes?.ami;
          const imageName = stateResource.instances[0].attributes?.image;

          if (amiId) {
            const result = execSync(
              `aws ec2 describe-images --image-ids ${amiId} --query "Images[0].{Name:Name,Description:Description}" --output json`,
              {
                env: {
                  AWS_ACCESS_KEY_ID: platform.keyId,
                  AWS_SECRET_ACCESS_KEY: platform.secretKey,
                  AWS_DEFAULT_REGION: deploymentData.original.region
                    ? deploymentData.original.region
                    : stateResource.instances[0].attributes.arn.split(":")[3],
                },
              },
            );

            const ami = JSON.parse(result.toString());
            const amiName = ami.Name.toLowerCase();
            const amiDescription = ami.Description.toLowerCase();

            if (
              amiName.includes("ubuntu") ||
              amiDescription.includes("ubuntu")
            ) {
              username = "ubuntu";
            } else if (amiName.includes("centos")) {
              username = "centos";
            } else if (amiName.includes("debian")) {
              username = "admin";
            } else if (amiName.includes("fedora")) {
              username = "fedora";
            } else {
              username = "ec2-user";
            }
          } else if (imageName) {
            // DigitalOcean uses root user
            username = "root";
          }

          await db
            .update(resources)
            .set({
              providerId: stateResource.instances[0].attributes.id,
              privateIp:
                stateResource.instances[0].attributes.private_ip ||
                stateResource.instances[0].attributes.ipv4_address_private ||
                stateResource.instances[0].attributes.cidr_block ||
                null,
              publicIp:
                stateResource.instances[0].attributes.public_ip ||
                stateResource.instances[0].attributes.ipv4_address ||
                null,
            })
            .where(eq(resources.id, resourceRow.id));
        }

        await db
          .update(infrastructure)
          .set({ status: "running", username })
          .where(eq(infrastructure.id, infrastructureRow.id));
      } catch (e) {
        console.error(e);
        await db
          .update(infrastructure)
          .set({ status: "failed" })
          .where(eq(infrastructure.deploymentId, deploymentId));
      }
    }

    await db
      .update(deployments)
      .set({ status: "ready-to-configure" })
      .where(eq(deployments.id, deploymentId));
  } catch {
    await db
      .update(deployments)
      .set({ status: "failed" })
      .where(eq(deployments.id, deploymentId));
  }
};

export const configureDeployment = async (req, res) => {
  const { deploymentId } = req.params;

  if (!deploymentId) {
    return res.status(400).json({ error: "error 'deploymentId' is required" });
  }

  const [deploymentData] = await db
    .update(deployments)
    .set({ status: "configuring" })
    .where(eq(deployments.id, deploymentId))
    .returning();

  if (!deploymentData) {
    return res.status(404).json({ error: "deployment not found" });
  }

  res.sendStatus(200);

  const [tailscaleKey] = await db
    .select()
    .from(integrations)
    .where(eq(integrations.id, deploymentData.tailscaleId));

  const infrastructureData = await db
    .select()
    .from(infrastructure)
    .where(eq(infrastructure.deploymentId, deploymentId));

  const templatesData = await db
    .select()
    .from(templates)
    .where(eq(templates.type, "configuration"));

  const deploymentDir = path.join(DEPLOYMENTS_DIR, deploymentId);
  const ansibleDir = path.join(deploymentDir, "ansible");
  const filesDir = path.join(deploymentDir, "files");

  const infrastructureWithConfigurations = infrastructureData.filter(
    (i) => i.configurations?.length > 0,
  );

  let inventoryFileContent = "forge:\n  hosts:\n";
  let mainPlaybookFileContent = "---";

  for (const infrastructure of infrastructureWithConfigurations) {
    const resourceData = await db
      .select()
      .from(resources)
      .where(eq(resources.infrastructureId, infrastructure.id));

    const tailscaleIp = resourceData.find(
      (resource) => resource.tailscaleIp !== null,
    )?.tailscaleIp;

    inventoryFileContent += `    ${infrastructure.id.split("-").join("_")}:\n      ansible_host: ${tailscaleIp}\n      ansible_user: ${infrastructure.username}\n`;

    for (const configuration of infrastructure.configurations || []) {
      const configurationTemplate = templatesData.find(
        (t) => t.id === configuration.template,
      );

      if (!configurationTemplate) continue;

      mainPlaybookFileContent += `\n- name: ${configuration.id}\n  import_playbook: ${configuration.id}.yml\n\n`;

      let ansibleData = await handleConfigurationVariables(
        configurationTemplate.value,
        configuration.variables,
        filesDir,
      );

      ansibleData = addHostToPlaybook(
        infrastructure.id.split("-").join("_"),
        ansibleData,
      );

      fs.writeFileSync(
        path.join(ansibleDir, `${configuration.id}.yml`),
        ansibleData,
        "utf8",
      );
    }
  }

  fs.writeFileSync(
    path.join(ansibleDir, "inventory.yml"),
    inventoryFileContent,
    "utf8",
  );

  fs.writeFileSync(
    path.join(ansibleDir, "main.yml"),
    mainPlaybookFileContent,
    "utf8",
  );

  const [tagSetting] = await db
    .select()
    .from(settings)
    .where(eq(settings.name, "tailscaleTag"));

  const tailscaleResult = await fetch(
    "https://api.tailscale.com/api/v2/tailnet/-/keys?all=true",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tailscaleKey.secretKey}`,
      },
      body: JSON.stringify({
        capabilities: {
          devices: {
            create: {
              reusable: false,
              ephemeral: true,
              preauthorized: true,
              tags: tagSetting ? [`tag:${tagSetting.value}`] : [],
            },
          },
          expirySeconds: 86400,
        },
      }),
    },
  );

  const newKey = await tailscaleResult.json();

  try {
    // Disconnect from tailscale before reconnecting (sometimes it remains connected)
    await runCommand(deploymentId, deploymentData.projectId, "tailscale", [
      "logout",
    ]);

    await runCommand(deploymentId, deploymentData.projectId, "tailscale", [
      "up",
      `--auth-key=${newKey.key}`,
      "--accept-dns=false",
      `--hostname=${
        String("lodestar-forge-nucleus" + "-" + deploymentId.split("-")[0])
          .toLowerCase() // Lowercase everything
          .replace(/[^a-z0-9-]+/g, "-") // Replace invalid characters with hyphen
          .replace(/^-+|-+$/g, "") // Trim leading/trailing hyphens
          .replace(/-+/g, "-") // Collapse multiple hyphens
          .slice(0, 63) // Trim to 63 characters max
      }`,
    ]);

    await runCommand(
      deploymentId,
      deploymentData.projectId,
      "ansible-playbook",
      ["-i", "inventory.yml", "--private-key=../private-key.pem", "main.yml"],
      {
        PATH: `${DEFAULT_PATH}:/root/.local/bin`,
        ANSIBLE_HOST_KEY_CHECKING: "False",
      },
      ansibleDir,
    );

    await db
      .update(deployments)
      .set({ status: "live" })
      .where(eq(deployments.id, deploymentId));
  } catch {
    await db
      .update(deployments)
      .set({ status: "failed" })
      .where(eq(deployments.id, deploymentId));
  } finally {
    // Disconnect from tailscale
    await runCommand(deploymentId, deploymentData.projectId, "tailscale", [
      "logout",
    ]);
  }
};

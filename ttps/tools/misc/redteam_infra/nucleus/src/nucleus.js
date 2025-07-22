import express from "express";
import dotenv from "dotenv";

// Import routes
import { router as authRoutes } from "./route/auth.js";
import { router as projectRoutes } from "./route/projects.js";
import { router as deploymentRoutes } from "./route/deployments.js";
import { router as sshKeyRoutes } from "./route/sshKeys.js";
import { router as userRoutes } from "./route/users.js";
import { router as integrationRoutes } from "./route/integrations.js";
import { router as templateRoutes } from "./route/templates.js";
import { router as domainRoutes } from "./route/domains.js";
import { router as dnsRoutes } from "./route/dns.js";
import { router as infrastructureRoutes } from "./route/infrastructure.js";
import { router as resourceRoutes } from "./route/resources.js";
import { router as logRoutes } from "./route/logs.js";
import { router as fileRoutes } from "./route/files.js";
import { router as settingRoutes } from "./route/settings.js";

// Import middlewares
import { authenticatedUser } from "./middleware/auth.js";
import { checkDeploymentMiddleware } from "./middleware/deployment.js";
import { checkDomainMiddleware } from "./middleware/domain.js";
import { checkInfrastructureMiddleware } from "./middleware/infrastructure.js";

// Configure env
dotenv.config();

// Configure express
const app = express();
const port = process.env.NUCLEUS_PORT;
app.use(express.json());

// Use routes
app.use("/auth", authRoutes);
app.use("/logs", logRoutes);
app.use("/ssh-keys", authenticatedUser, sshKeyRoutes);
app.use("/users", authenticatedUser, userRoutes);
app.use("/integrations", authenticatedUser, integrationRoutes);
app.use("/templates", authenticatedUser, templateRoutes);
app.use("/files", authenticatedUser, fileRoutes);
app.use("/settings", authenticatedUser, settingRoutes);
app.use("/projects", authenticatedUser, projectRoutes);
app.use("/domains", authenticatedUser, domainRoutes);
app.use(
    "/domains/:domainId/dns",
    [authenticatedUser, checkDomainMiddleware],
    dnsRoutes,
);
app.use("/deployments", authenticatedUser, deploymentRoutes);
app.use(
    "/deployments/:deploymentId/infrastructure",
    [authenticatedUser, checkDeploymentMiddleware],
    infrastructureRoutes,
);
app.use(
    "/deployments/:deploymentId/infrastructure/:infrastructureId/resources",
    [
        authenticatedUser,
        checkDeploymentMiddleware,
        checkInfrastructureMiddleware,
    ],
    resourceRoutes,
);

// Start server
app.listen(port, () => {
    console.log(`Nucleus listening on port ${port}`);
});

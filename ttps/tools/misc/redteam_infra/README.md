<!-- ABOUT THE PROJECT -->
## About The Project
![Lodestar Forge Screen Shot](/images/overview.gif)

> [!CAUTION]
> Lodestar Forge is still in early development. Some feautres of the platform may be unstable and therefore all infrastructure should be verified manually directly within your cloud provider console. We are not responsible for any unexpected billing which may occur due to bugs in the platform.

Introducing Lodestar Forge (or Forge), an infrastructure creation and management platform, specifically designed for red team engagements.

Red team operations often demand rapidly deployable, flexible, and covert infrastructure—yet existing tools are either too generalised, too manual, or not built with offensive operations in mind. Forge was created to fill this gap.

Forge is designed for operators - It abstracts away the complexity of managing infrastructure during engagements, so you can focus on what matters: executing your objectives. Whether you’re simulating APT-level threats, running internal red team campaigns, or building resilient test environments, Forge enables consistent and repeatable deployments at scale.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Features

✅ **Clean and simple UI** - Ensures speed and usablility, allowing you to focus on what matters during a red team engagement.

✅ **Cross-Cloud Compatibility** - Forge supports deployments across multiple cloud providers (currently AWS and DigitalOcean), offering flexibility and redundancy.

✅ **Scalability** - Design infrastructure to scale horizontally, accommodating varying sizes of engagements and adapting to changing operational requirements.

✅ **Modular Architecture** - Design infrastructure components (e.g., C2 servers, redirectors, phishing servers) as interchangeable templates, allowing for flexible and reusable configurations tailored to specific engagement needs.

✅ **Infrastructure as Code** - Leverage tools like Terraform and Ansible to define, deploy, and manage infrastructure consistently across various environments.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


### Built With

This section lists any major frameworks/libraries used to make this project happen:

* React Framework: [Next.js](https://nextjs.org)
* Component Library: [shadcn/ui](https://ui.shadcn.com)
* Database ORM: [DrizzleORM](https://orm.drizzle.team)
* Infrastructure as Code: [Terraform](https://developer.hashicorp.com/terraform)
* Configurations as Code: [Ansible](https://www.redhat.com/en/ansible-collaborative)
* General Docs: [Aria Docs](https://github.com/nisabmohd/Aria-Docs)
* API Docs: [Scalar](https://scalar.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

Below is the getting started guide for Forge. Please refer to the documentation [here](https://docs.lodestar-forge.com/) or steps below for our quickstart guide.

### Prerequisites
The following prerequisites are required to get started with Forge:

* Docker
* Docker Compose

The following prerequisites are required to deploy infrastructure with Forge:

* An AWS or Digital Ocean account
* Tailscale


### Installation

1. To get started with Forge, first clone this GitHub repository.
```bash

```

2. Create a `.env` environment file and customise your Forge instance. 
```bash
chmod +x gen-env.sh && ./gen-env.sh
```

3. Bring up Forge using Docker compose:
```
docker compose up
```

4. Access Forge in a web browser at `http://your.hostname.com:3000/`. You can authenticate with the default credentials, which will be displayed in the docker logs on first launch.


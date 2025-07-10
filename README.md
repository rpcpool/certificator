# Triton Certificator

This is a fork of [vinted's certificator](https://github.com/vinted/certificator) tool with customisations made to support our specific use-case, which has removed upstream features, which we have not (yet) attempted to upstream.

As such this repository has been stripped down, removing various upstream tests which are no longer valid. These can be reintroduced if they are fixed, but there's no value to keeping them while they are not.

We have also added a devcontainer and a workflow for building the application container ready for use in nomad.
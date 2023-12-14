#!/bin/bash

pipenv run main \
    --github-policy advanced-security/policy-as-code \
    --github-policy-path examples/policies/conditions.yml

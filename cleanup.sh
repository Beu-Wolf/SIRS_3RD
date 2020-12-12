#!/bin/bash

# Clean Backup files and tmp folders
rm -r Backup/files/*
rm -r Backup/tmp/*

# Clean Server files and tmp folder
rm -r Server/files/*
rm -r Server/tmp/*

# Clean Client files and tmp folder (keep sharedFiles folder)
rm -r Client/files/sharedFiles/*
rm Client/files/*
rm -r Client/tmp/*

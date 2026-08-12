import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from jschon import JSON, JSONSchema, create_catalog

from lib.util import output_errors

BASEDIR = 'ca'

# Ensure our output directories exist
for dir in [BASEDIR, os.path.join(BASEDIR, 'private'), os.path.join(BASEDIR, 'certs'), os.path.join(BASEDIR, 'crls')]:
    if not os.path.isdir(dir):
        os.mkdir(dir)


@dataclass(frozen=True)
class PDSLocation:
    url: str
    language: str

    @classmethod
    def from_dict(cls, data: dict) -> "PDSLocation":
        return cls(
            url=data["url"],
            language=data["language"]
        )

    def as_dict(self) -> dict:
        return {
                'url': self.url,
                'language': self.language
            }
    

@dataclass(frozen=True)
class Config:
    log_filename: str = 'ca/events.txt'
    ca_issuers_base_url: str = 'http://cert.pkioverheid.nl'
    crl_distribution_points_base_url: str = 'http://crl.pkioverheid.nl'
    crl_renewal_hours: int = 48
    pds_location: PDSLocation = PDSLocation('https://www.github.com/pkioverheid/g4-trial', 'en')

    @classmethod
    def from_file(cls, filename: str) -> "Config":
        try:
            with Path(filename).open("r", encoding="utf-8") as f:
                return cls.from_yaml(f.read(0))
        except SyntaxError as e:
            raise SyntaxError(f"Configuration file {filename} is invalid") from e

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "Config":
        data = yaml.safe_load(yaml_str)

        create_catalog("2020-12")
        schema = JSONSchema.loadf(os.path.join('schema', 'config.json'))

        instance = JSON(data)
        result = schema.evaluate(instance)
        if not result.valid:
            print(f"Invalid configuration: ")
            output_errors(result.output("detailed")["errors"])
            raise SyntaxError(f"Invalid configuration")

        return cls(
            log_filename=data["logFilename"],
            ca_issuers_base_url=data["caIssuersBaseUrl"],
            crl_distribution_points_base_url=data["cRLDistributionPointsBaseUrl"],
            crl_renewal_hours=data["crlRenewalHours"],
            pds_location=PDSLocation(data["pdsLocation"]["url"], data["pdsLocation"]["language"])
        )

    def as_dict(self) -> dict:
        return {
            'logFilename': self.log_filename,
            'caIssuersBaseUrl': self.ca_issuers_base_url,
            'cRLDistributionPointsBaseUrl': self.crl_distribution_points_base_url,
            'crlRenewalHours': self.crl_renewal_hours,
            'pdsLocation': self.pds_location.as_dict()
        }


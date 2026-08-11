import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from jschon import JSON, JSONSchema, create_catalog

from lib.util import output_errors


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
    base_dir: str = 'ca'
    log_filename: str = 'events.txt'
    ca_issuers_base_url: str = 'http://cert.pkioverheid.nl'
    crl_distribution_points_base_url: str = 'http://crl.pkioverheid.nl'
    crl_renewal_hours: int = 48
    pds_location: PDSLocation = PDSLocation('https://www.github.com/pkioverheid/g4-trial', 'en')

    log_path = property(lambda self: os.path.join(self.base_dir, self.log_filename))

    def init(self) -> "Config":
        # Ensure our output directories exist
        for dir in [
                self.base_dir, 
                os.path.join(self.base_dir, 'private'), 
                os.path.join(self.base_dir, 'certs'), 
                os.path.join(self.base_dir, 'crl')
            ]:
            if not os.path.isdir(dir):
                os.mkdir(dir)
        return self
    
    @classmethod
    def from_file(cls, filename: str) -> "Config":
        try:
            with Path(filename).open("r", encoding="utf-8") as f:
                return cls.from_yaml(f.read())
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
            base_dir=data["baseDir"],
            log_filename=data["logFilename"],
            ca_issuers_base_url=data["caIssuersBaseUrl"],
            crl_distribution_points_base_url=data["cRLDistributionPointsBaseUrl"],
            crl_renewal_hours=data["crlRenewalHours"],
            pds_location=PDSLocation(data["pdsLocation"]["url"], data["pdsLocation"]["language"])
        ).init()

    def as_dict(self) -> dict:
        return {
            'baseDir': self.base_dir,
            'logFilename': self.log_filename,
            'caIssuersBaseUrl': self.ca_issuers_base_url,
            'cRLDistributionPointsBaseUrl': self.crl_distribution_points_base_url,
            'crlRenewalHours': self.crl_renewal_hours,
            'pdsLocation': self.pds_location.as_dict()
        }

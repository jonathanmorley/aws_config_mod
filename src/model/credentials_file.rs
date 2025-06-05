//! Handles parsing, reading, and updating values of aws credntials files.

use super::SectionName;
use super::{header::CredentialHeader, whitespace::Whitespace, Section};
use crate::lexer::{to_owned_input, Parsable};
use crate::{SettingPath, Value};
use nom::Parser;
use nom::{combinator::eof, multi::many0, sequence::tuple};
use std::fmt::Display;
use std::str::FromStr;

/// Represents and aws credentials file. A credentials file contains sensitive authentication information
/// separately from the main configuration file.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AwsCredentialsFile {
    /// Whitespace and comments at the head of the file, before the first section
    pub(crate) leading_whitespace: Whitespace,

    /// Represents the content of the file. The content includes the sections representing
    /// the authentication credentials of specific profiles.
    pub(crate) profiles: Vec<Section<CredentialHeader>>,

    /// Whitespace and comments at the end of the file, after the end of the last section
    pub(crate) trailing_whitespace: Whitespace,
}

impl AwsCredentialsFile {
    /// Initialize an empty credentials file
    pub fn new() -> Self {
        Self {
            leading_whitespace: Whitespace::default(),
            profiles: vec![],
            trailing_whitespace: Whitespace::newline(),
        }
    }

    // TODO: rename 'get section'. Add a strongly typed struct for CredentialProfile and use 'get_profile' for that
    /// Get an immutable reference to the credentials for a given profile
    pub fn get_profile(&self, profile_name: SectionName) -> Option<&Section<CredentialHeader>> {
        self.profiles
            .iter()
            .find(|profile| *profile.get_name() == profile_name)
    }

    /// Get a mutable reference to the credentials for a given profile
    pub fn get_profile_mut(
        &mut self,
        profile_name: SectionName,
    ) -> Option<&mut Section<CredentialHeader>> {
        self.profiles
            .iter_mut()
            .find(|profile| *profile.get_name() == profile_name)
    }

    // TODO: replace SettingPath with a more generic path
    /// Provided a [SettingPath] and a [Value], locates the desired [Setting] and changes its [Value].
    /// If the setting doesn't exist, it will be created. If the [Section] that contains the [Setting]
    /// doesn't exist, it will also be created.
    pub fn set(&mut self, setting_path: SettingPath, value: Value) {
        // If the section type is not a profile, we cannot set it in a credentials file
        if let Some(section_name) = setting_path.section_path.section_name {
            let profile = match self.get_profile_mut(section_name.clone()) {
                Some(section) => section,
                None => self.insert_profile(section_name),
            };

            profile.set(setting_path.setting_name, value);
        } else {
            // If the section name is None, we cannot set it in a credentials file
            panic!("Cannot set a setting without a section name in a credentials file");
        }
    }

    /// Check if the given [Section] exists from a [SectionPath]
    pub(crate) fn contains_profile(&self, profile_name: &SectionName) -> bool {
        self.profiles.iter().any(|section| section.get_name() == profile_name)
    }

    /// Given a [SectionPath], create the [Section] if it doesn't exist and return a mutable
    /// reference to it.
    pub(crate) fn insert_profile(
        &mut self,
        profile_name: SectionName,
    ) -> &mut Section<CredentialHeader> {
        if !self.contains_profile(&profile_name) {
            let new_profile: Section<CredentialHeader> =
                Section::new(CredentialHeader::new(profile_name.clone()));
            self.profiles.push(new_profile);
        }

        #[allow(clippy::unwrap_used)]
        // This cannot fail because we just added the item if it didn't exist
        self.get_profile_mut(profile_name).unwrap()
    }
}

impl Display for AwsCredentialsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            self.leading_whitespace,
            self.profiles
                .iter()
                .map(Section::to_string)
                .collect::<String>(),
            self.trailing_whitespace
        )
    }
}

impl<'a> Parsable<'a> for AwsCredentialsFile {
    type Output = Self;

    fn parse(input: &'a str) -> crate::lexer::ParserOutput<'a, Self::Output> {
        let (next, ((leading_whitespace, profiles, trailing_whitespace), _)) = tuple((
            Whitespace::parse,
            many0(Section::<CredentialHeader>::parse),
            Whitespace::parse,
        ))
        .and(eof)
        .parse(input)?;

        let config_file = Self {
            leading_whitespace,
            profiles,
            trailing_whitespace,
        };

        Ok((next, config_file))
    }
}

impl FromStr for AwsCredentialsFile {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
            .map(|a| a.1)
            .map_err(to_owned_input)
            .map_err(crate::Error::from)
    }
}

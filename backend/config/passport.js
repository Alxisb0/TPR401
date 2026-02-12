const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const {
  findUserByGoogleId,
  createUserFromGoogle,
  findUserByGithubId,
  createUserFromGithub,
  findUserByDiscordId,
  createUserFromDiscord
} = require('../models/User');

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const db = req.app.locals.db;

        let user = await findUserByGoogleId(db, profile.id);

        if (!user) {
          user = await createUserFromGoogle(db, {
            googleId: profile.id,
            email: profile.emails?.[0]?.value || null,
            name: profile.displayName,
            picture: profile.photos?.[0]?.value || null
          });
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);





const GitHubStrategy = require('passport-github2').Strategy;

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const db = req.app.locals.db;

        let user = await findUserByGithubId(db, profile.id);

        if (!user) {
          user = await createUserFromGithub(db, {
            githubId: profile.id,
            email: profile.emails?.[0]?.value || null,
            name: profile.displayName,
            picture: profile.photos?.[0]?.value || null
          });
        }


        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);


const DiscordStrategy = require('passport-discord').Strategy;

passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_CALLBACK_URL,
      scope: ['identify', 'email'],
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const db = req.app.locals.db;

        let user = await findUserByDiscordId(db, profile.id);

        if (!user) {
          user = await createUserFromDiscord(db, {
            discordId: profile.id,
            email: profile.email,
            name: profile.username,
            picture: `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
          });
        }


        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);



module.exports = passport;

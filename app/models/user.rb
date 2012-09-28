# -*- coding: utf-8 -*-
class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :token_authenticatable, :encryptable, :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :rememberable, :trackable, :validatable, :omniauthable

  # Setup accessible (or protected) attributes for your model
  attr_accessible :email, :password, :password_confirmation, :remember_me, :name, :image, :default_provider_id

  has_many :providers_users, :dependent => :destroy
  has_many :providers, :through => :providers_users
  has_many :sites, :dependent => :destroy

  def self.find_for_facebook_oauth(auth, current_user = nil)
    providers_user = ProvidersUser.find_by_provider_id_and_user_key Provider.facebook.id, auth['uid'].to_s
    begin
      profiles = SocialSync::Facebook.profiles auth['credentials']['token'], {:uid => [auth['uid']]}
      name = profiles[0][:name]
      image = profiles[0][:pic_square]
    rescue => e
      logger.error e
      name = auth['info']['name']
      image = auth['info']['image'].gsub(/(type=)(.*)/, '\1')
    end
    email = auth['info']['email']
    uid = auth['uid'].to_s
    token = auth['credentials']['token']
    secret = auth['credentials']['secret']

    logger.info auth.to_yaml

    user = get_user_from_hoge(providors_user, current_user, Provider.twitter.id, auth, name, image, email, uid, token, seret)
  end

  def self.find_for_twitter_oauth(auth, current_user = nil)
    providers_user = ProvidersUser.find_by_provider_id_and_user_key Provider.twitter.id, auth['uid'].to_s

    name = auth['info']['nickname']
    image = auth['info']['image']
    email = "#{auth['uid']}@twitter.example.com" # twitter return no email, so set dummy email address because of email wanne be unique.
    uid = auth['uid'].to_s
    token = auth['credentials']['token']
    secret = auth['credentials']['secret']

    user = get_user_from_hoge(providors_user, current_user, Provider.twitter.id, auth, name, image, email, uid, token, secret)
  end

  def self.find_for_github_oauth(auth, current_user = nil)
    providers_user = ProvidersUser.find_by_provider_id_and_user_key Provider.github.id, auth['uid'].to_s
    name = auth['info']['nickname']
    image = auth['extra']['raw_info']['avatar_url']
    email = auth['info']['email']||"#{auth['uid']}@github.example.com"
    uid = auth['uid'].to_s
    token = auth['credentials']['token']
    secret = auth['credentials']['secret']

    user = get_user_from_hoge(providors_user, current_user, Provider.github.id, uid, name, image, email, uid, token)
  end

  def self.find_or_create_from_auth_infos(providors_user, current_user, provider_id, name, image, email, uid, token, secret = nil)
    if providers_user.nil?
      user = current_user || User.create!({
        :password => Devise.friendly_token[0,20],
        :name => name,
        :email => email,
        :image => image,
        :default_provider_id => provider_id
      })
    else
      user = User.find providers_user[:user_id]
      if current_user.nil?
        user.default_provider_id = provider_id
      end
      if user.default_provider_id == provider_id
        user.name = name
        user.image = image
      end
      user.save!
    end

    providors_user ||= ProvidersUser.new
    providors_user.provider_id = provider_id
    providors_user.user_id = user.id
    providors_user.user_key = uid
    providors_user.access_token = token
    providors_user.secret = secret
    providors_user.name = name
    providors_user.email = email
    providors_user.image = image
    providers_user.save!

    user
  end

  def self.find_by_path provider_name, user_key
    providers_user = ProvidersUser.where(:provider_id => Provider.send(provider_name).id, :user_key => user_key).first
    self.includes(:sites).find providers_user.user_id
  end

  def user_key
    self.providers_users.where(:provider_id => self.default_provider_id).first.user_key
  end

  def default_provider
    Provider.select('id, name').find self.default_provider_id
  end

  def has_provider? provider_id
    self.providers_users.select(:provider_id).map{|providers_user|providers_user.provider_id}.include? provider_id
  end

  def has_all_provider?
    self.providers_users.length === Provider.all.length
  end
end

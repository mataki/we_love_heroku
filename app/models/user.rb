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
    logger.info auth.to_yaml
    user = get_user_from_hoge(providors_user, current_user, auth, email, Provider.twitter.id)
  end

  def self.find_for_twitter_oauth(auth, current_user = nil)
    providers_user = ProvidersUser.find_by_provider_id_and_user_key Provider.twitter.id, auth['uid'].to_s

    name = auth['info']['nickname']
    image = auth['info']['image']
    email = "#{auth['uid']}@twitter.example.com" # twitter return no email, so set dummy email address because of email wanne be unique.

    user = get_user_from_hoge(providors_user, current_user, auth, email, Provider.twitter.id)
  end

  def self.find_for_github_oauth(auth, current_user = nil)
    providers_user = ProvidersUser.find_by_provider_id_and_user_key Provider.github.id, auth['uid'].to_s
    name = auth['info']['nickname']
    image = auth['extra']['raw_info']['avatar_url']
    email = auth['info']['email']||"#{auth['uid']}@github.example.com"

    user = get_user_from_hoge(providors_user, current_user, auth, email, Provider.github.id)
  end

  def self.find_or_create_from_auth_infos(providors_user, current_user, email, auth, provider_id)
    if providers_user.nil?
      if current_user.nil?
        user = User.create!({
          :password => Devise.friendly_token[0,20],
          :name => name,
          :email => email,
          :image => image,
          :default_provider_id => provider_id
        })
      else
        user = current_user
      end
      providers_user = ProvidersUser.create!({
        :provider_id => provider_id,
        :user_id => user.id,
        :user_key => auth['uid'].to_s,
        :access_token => auth['credentials']['token'],
        :secret => auth['credentials']['secret'],
        :name => name,
        :email => email,
        :image => image,
      })
    else
      user = User.find providers_user[:user_id]
      if current_user.nil?
        user.default_provider_id = provider_id
        user.save!
      end
      if user.default_provider_id == provider_id
        user.name = name
        user.image = image
        user.save!
      end

      providers_user.name = name
      providers_user.image = image
      providers_user.email = email
      providers_user.access_token = auth['credentials']['token']
      providers_user.secret = auth['credentials']['secret']
      providers_user.save!
    end
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

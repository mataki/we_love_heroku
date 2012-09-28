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
    data = build_data_from_auth(auth) do |data|
      begin
        profiles = SocialSync::Facebook.profiles auth['credentials']['token'], {:uid => [auth['uid']]}
        data[:name] = profiles[0][:name]
        data[:image] = profiles[0][:pic_square]
      rescue => e
        logger.error e
        data[:name] = auth['info']['name']
        data[:image] = auth['info']['image'].gsub(/(type=)(.*)/, '\1')
      end
      data[:email] = auth['info']['email']
    end

    provider_id = Provider.facebook.id

    find_or_create_from_auth_infos(data, provider_id, current_user)
  end

  def self.find_for_twitter_oauth(auth, current_user = nil)
    data = build_data_from_auth(auth) do |data|
      data[:name] = auth['info']['nickname']
      data[:image] = auth['info']['image']
      data[:email] = "#{auth['uid']}@twitter.example.com" # twitter return no email, so set dummy email address because of email wanne be unique.
      data[:secret] = auth['credentials']['secret']
    end

    provider_id = Provider.twitter.id

    find_or_create_from_auth_infos(data, provider_id, current_user)
  end

  def self.find_for_github_oauth(auth, current_user = nil)
    data = build_data_from_auth(auth) do |data|
      data[:name] = auth['info']['nickname']
      data[:image] = auth['extra']['raw_info']['avatar_url']
      data[:email] = auth['info']['email'] || "#{auth['uid']}@github.example.com"
    end

    provider_id = Provider.github.id

    find_or_create_from_auth_infos(data, provider_id, current_user)
  end

  def self.build_data_from_auth(auth)
    result = {:user_key => auth['uid'].to_s, :access_token => auth['credentials']['token']}
    yield result if block_given?
    result
  end

  def self.find_or_create_from_auth_infos(data, provider_id, current_user)
    providers_user = ProvidersUser.find_or_initialize_by_provider_id_and_user_key(provider_id, data[:user_key])

    if providers_user.new_record?
      providers_user.user = current_user || User.new({
        :password => Devise.friendly_token[0,20],
        :name => data[:name],
        :email => data[:email],
        :image => data[:image],
        :default_provider_id => provider_id
      })
    end
    providers_user.attributes = data

    user = providers_user.user
    if current_user.nil?
      user.default_provider_id = provider_id
    end
    if user.default_provider_id == provider_id
      user.name = data[:name]
      user.image = data[:image]
    end

    transaction do
      user.save!
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

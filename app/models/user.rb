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
    find_or_create_from_auth_infos(auth, :facebook, current_user)
  end

  def self.find_for_twitter_oauth(auth, current_user = nil)
    find_or_create_from_auth_infos(auth, :twitter, current_user)
  end

  def self.find_for_github_oauth(auth, current_user = nil)
    find_or_create_from_auth_infos(auth, :github, current_user)
  end

  def self.auth_to_info_hash(auth, provider)
    result = {}
    case provider
    when :facebook
      begin
        profiles = SocialSync::Facebook.profiles auth['credentials']['token'], {:uid => [auth['uid']]}
        result[:name] = profiles[0][:name]
        result[:image] = profiles[0][:pic_square]
      rescue => e
        logger.error e
        result[:name] = auth['info']['name']
        result[:image] = auth['info']['image'].gsub(/(type=)(.*)/, '\1')
      end
      result[:email] = auth['info']['email']

    when :twitter
      result[:name] = auth['info']['nickname']
      result[:image] = auth['info']['image']
      result[:email] = "#{auth['uid']}@twitter.example.com" # twitter return no email, so set dummy email address because of email wanne be unique.
      result[:secret] = auth['credentials']['secret']

    when :github
      result[:name] = auth['info']['nickname']
      result[:image] = auth['extra']['raw_info']['avatar_url']
      result[:email] = auth['info']['email'] || "#{auth['uid']}@github.example.com"
    end
    result[:uid] = auth['uid'].to_s
    result[:token] = auth['credentials']['token']

    result
  end

  def self.find_or_create_from_auth_infos(auth, provider_name, current_user)
    data = auth_to_info_hash(auth, provider_name)

    provider_id = Provider.send(provider_name).id
    providers_user = ProvidersUser.find_by_provider_id_and_user_key provider_id, auth['uid'].to_s
    if providers_user.nil?
      user = current_user || User.create!({
        :password => Devise.friendly_token[0,20],
        :name => data[:name],
        :email => data[:email],
        :image => data[:image],
        :default_provider_id => provider_id
      })
    else
      user = User.find providers_user[:user_id]
      if current_user.nil?
        user.default_provider_id = provider_id
      end
      if user.default_provider_id == provider_id
        user.name = data[:name]
        user.image = data[:image]
      end
      user.save!
    end

    providers_user ||= ProvidersUser.new
    providers_user.provider_id = provider_id
    providers_user.user_id = user.id
    providers_user.attributes = data
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

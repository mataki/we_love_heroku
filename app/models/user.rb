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
    data = {:uid => auth['uid'].to_s, :access_token => auth['credentials']['token']}
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

    provider_id = Provider.facebook.id

    find_or_create_from_auth_infos(data, provider_id, current_user)
  end

  def self.find_for_twitter_oauth(auth, current_user = nil)
    data = {:uid => auth['uid'].to_s, :access_token => auth['credentials']['token']}
    data[:name] = auth['info']['nickname']
    data[:image] = auth['info']['image']
    data[:email] = "#{auth['uid']}@twitter.example.com" # twitter return no email, so set dummy email address because of email wanne be unique.
    data[:secret] = auth['credentials']['secret']

    provider_id = Provider.twitter.id

    find_or_create_from_auth_infos(data, provider_id, current_user)
  end

  def self.find_for_github_oauth(auth, current_user = nil)
    data = {:uid => auth['uid'].to_s, :access_token => auth['credentials']['token']}
    data[:name] = auth['info']['nickname']
    data[:image] = auth['extra']['raw_info']['avatar_url']
    data[:email] = auth['info']['email'] || "#{auth['uid']}@github.example.com"

    provider_id = Provider.github.id

    find_or_create_from_auth_infos(data, provider_id, current_user)
  end

  def self.find_or_create_from_auth_infos(data, provider_id, current_user)
    providers_user = ProvidersUser.find_by_provider_id_and_user_key provider_id, data['uid']

    user = if providers_user.nil?
             current_user || User.create!({
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
             user
           end

    providers_user ||= ProvidersUser.new
    providers_user.provider_id = provider_id
    providers_user.user_id = user.id
    providers_user.access_token = data.delete(:token)
    providers_user.attributes = data.delete_if{|k,_| k == :uid}
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

require 'resolv'
class Site < ActiveRecord::Base
  attr_accessible :user_id, :name, :url, :description, :creator, :hash_tag, :repository_url, :scheduled_access, :please_design
  validates_presence_of :name, :url, :creator
  validates_length_of :name, :minimum => 3, :maximum => 100
  validates_length_of :url, :minimum => 3, :maximum => 100
  validates_length_of :description, :minimum => 0, :maximum => 1000
  validates_length_of :creator, :minimum => 1, :maximum => 100
  validates_length_of :hash_tag, :minimum => 0, :maximum => 140
  validates_uniqueness_of :url
  validates_url_format_of :url
  validates_url_format_of :repository_url, :allow_nil => true, :allow_blank => true
  validate :url_is_heroku?

  belongs_to :user

  scope :search, lambda {|keyword| where(["
    name LIKE ? OR
    url LIKE ? OR
    description LIKE ? OR
    creator LIKE ? OR
    hash_tag LIKE ? OR
    repository_url LIKE ?
    ",
    "%#{keyword}%", "%#{keyword}%", "%#{keyword}%",
    "%#{keyword}%", "%#{keyword}%", "%#{keyword}%"
  ])}
  scope :please_designed, where(:please_design => TRUE)

  def hash_tags
    '#' + self.hash_tag.split(' ').join(' #')
  end

  def domain
    self.url.gsub(%r{http(?:s)?://([^/]+).+}, '\1')
  end

  def host_ipaddress
    @ipaddress ||= Resolv.getaddress(self.domain)
  end

  def same_creators
    Site.where(:creator => self.creator)
  end

  def same_creators_without_self
    same_creators.where("id != ?", self.id)
  end

  def self.pickups
    Rails.cache.fetch("model_site_pickups", :expires_in => 15.minutes) do
      Site.all.sort_by{rand}[0..2]
    end
  end

  private
  def url_is_heroku?
    return if self.url =~ /heroku(app)?\.com\/?/
    return true if Rails.env.test?
    return if self.domain.blank?
    unless APP_CONFIG[:heroku][:custom_domain].include? host_ipaddress
      unless Resolv::DNS.new.getresource(host, Resolv::DNS::Resource::IN::ANY).name.to_s =~ /heroku(app|ssl)?\.com\/?/
        errors.add :url, ' does not appear to be a valid heroku URL'
      end
    end
  rescue => e
    logger.error e.message
    e.backtrace.each{ |line| logger.error line }
    errors.add :url, ' does not appear to be a valid heroku URL'
    return
  end
end

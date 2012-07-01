require 'resolv'
class Site < ActiveRecord::Base
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
  
  def hash_tags
    '#' + self.hash_tag.split(' ').join(' #')
  end
  
  def domain
    self.url.gsub(%r{http(?:s)?://([^/]+).+}, '\1')
  end
  
  def same_creators
    Site.where(:creator => self.creator)
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
    if self.url =~ /http(?:s)?:\/\/([^\/]+)/
      host = $1
      begin
        ipaddress = Resolv.getaddress host
      rescue => e
        logger.error e.message
        errors.add :url, ' does not appear to be a valid heroku URL' 
        return
      end
      unless APP_CONFIG[:heroku][:custom_domain].include? ipaddress
        begin
          cname = Resolv::DNS.new.getresource(host, Resolv::DNS::Resource::IN::ANY).name
        rescue => e
          logger.error e.message
          errors.add :url, ' does not appear to be a valid heroku URL'
          return
        end
        return if cname =~ /heroku(app|ssl)?\.com\/?/
      end
    end

  end
end

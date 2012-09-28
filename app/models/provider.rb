class Provider < ActiveRecord::Base
  has_many :users, :through => :providers_users

  class << self
    %w(facebook twitter github).each do |providor|
      define_method(providor) do
        find_by_provider_name providor
      end
    end
  end

  private
  def self.find_by_provider_name provider_name
    Rails.cache.fetch("model_provider_#{provider_name}", :expires_in => 365.days) do
      select(:id).find_by_name(provider_name)
    end
  end
end
